package b4dpxl.timestamp;

import b4dpxl.Utilities;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import com.github.lgooddatepicker.components.DatePickerSettings;
import com.github.lgooddatepicker.components.DateTimePicker;
import com.github.lgooddatepicker.components.TimePickerSettings;
import com.github.lgooddatepicker.optionalusertools.PickerUtilities;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class TimestampEditor implements IContextMenuFactory, ActionListener {

    private IContextMenuInvocation invocation;

    public TimestampEditor(IBurpExtenderCallbacks callbacks) {
        new Utilities(callbacks, false);

        Utilities.callbacks.setExtensionName("Timestamp editor");
        Utilities.callbacks.registerContextMenuFactory(this);

    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

        ArrayList<JMenuItem> menu = new ArrayList<>();

        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
            JMenuItem item = new JMenuItem("Edit timestamp");
            item.addActionListener(this);

            TimestampDate date = extractTimestamp(invocation);
            if (date != null) {
                this.invocation = invocation;
                item.setToolTipText(date.toString());
                item.setEnabled(true);
            } else {
                item.setEnabled(false);
            }
            menu.add(item);
        } else {
            TimestampDate date = extractTimestamp(invocation);
            if (date != null) {
                JMenuItem item = new JMenuItem("View Timestamp");
                item.setToolTipText(date.toString());
                item.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        JTextArea jta = new JTextArea(date.toString());
                        jta.setColumns(30);
                        jta.setEditable(false);
                        int result = JOptionPane.showOptionDialog(
                                null,
                                jta,
                                "Timestamp",
                                JOptionPane.YES_NO_OPTION,
                                JOptionPane.PLAIN_MESSAGE,
                                null,
                                new Object[] {"Copy", "Close"},
                                null
                        );
                        if (result == JOptionPane.YES_OPTION) {
                            //copy to clipboard
                            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(date.toString()), null);
                        }
                    }
                });
                menu.add(item);
            }

        }

        return menu;

    }

    private TimestampDate extractTimestamp(IContextMenuInvocation invocation) {
        int[] bounds = invocation.getSelectionBounds();
        if (invocation.getSelectedMessages() != null) {
            byte[] messageBytes;
            switch(invocation.getInvocationContext()) {
                case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
                case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
                    messageBytes = invocation.getSelectedMessages()[0].getRequest();
                    break;
                case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
                case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
                    messageBytes = invocation.getSelectedMessages()[0].getResponse();
                    break;
                default:
                    Utilities.debug("Cannot extract selection");
                    return null;
            }
            String message = Utilities.helpers.bytesToString(messageBytes);
            try {
                long timestamp = Long.parseLong(message.substring(bounds[0], bounds[1]));
                if (timestamp > 9999999999999L) {
                    // microseconds
                    return new MicrosecondsTimestampDate(timestamp);
                } else if (timestamp <= 9999999999L) {
                    // seconds
                    return new SecondsTimestampDate(timestamp);
                }
                return new TimestampDate(timestamp);
            } catch (NumberFormatException e) {
                Utilities.debug("Not a timestamp");
            }
        }
        return null;
    }

    @Override
    public void actionPerformed(ActionEvent evt) {
        if (invocation == null) {
            return;
        }

        TimestampDate date = extractTimestamp(invocation);
        Utilities.debug("Date: " + date.toString());

        DatePickerSettings dateSettings = new DatePickerSettings();
        dateSettings.setFirstDayOfWeek(DayOfWeek.MONDAY);
        dateSettings.setVisibleClearButton(false);
        dateSettings.setColor(DatePickerSettings.DateArea.TextMonthAndYearMenuLabels, Color.BLACK);
        dateSettings.setColor(DatePickerSettings.DateArea.TextTodayLabel, Color.BLACK);
        TimePickerSettings timeSettings = new TimePickerSettings();
        timeSettings.setFormatForDisplayTime(
                PickerUtilities.createFormatterFromPatternString("HH:mm:ss", timeSettings.getLocale())
        );

        DateTimePicker picker = new DateTimePicker(dateSettings, timeSettings);
        picker.setDateTimeStrict(date.getLocalDateTime());

        Box box = Box.createHorizontalBox();
        box.setAlignmentX(Box.LEFT_ALIGNMENT);
        box.add(picker);

        JButton button = new JButton("Copy");
        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                // Thu Feb 25 13:13:59 GMT 2021
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                        new StringSelection(picker.getDateTimeStrict().atZone(ZoneId.of("UTC")).format(DateTimeFormatter.RFC_1123_DATE_TIME)),
                        null
                );
            }
        });
        box.add(button);

        int results = JOptionPane.showConfirmDialog(
                null,
                new JScrollPane(box),
                "Choose Date/Time",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );

        if (results == JOptionPane.OK_OPTION) {
            date.setTime(picker.getDateTimeStrict());
            Utilities.debug(date.getTimestamp());
            int[] bounds = invocation.getSelectionBounds();
            byte[] request = invocation.getSelectedMessages()[0].getRequest();
            String message = Utilities.helpers.bytesToString(request);

            StringBuilder builder = new StringBuilder(message.substring(0, bounds[0]))
                    .append(date.getTimestamp())
                    .append(message.substring(bounds[1]));

            invocation.getSelectedMessages()[0].setRequest(Utilities.helpers.stringToBytes(builder.toString()));
        }


        invocation = null;
    }

    class SecondsTimestampDate extends TimestampDate {

        public SecondsTimestampDate(long date) {
            super(date * 1000L);
        }

        public long getTimestamp() {
            return super.getTime() / 1000L;
        }

    }

    class MicrosecondsTimestampDate extends TimestampDate {

        public MicrosecondsTimestampDate(long date) {
            super(date / 1000L);
        }

        public long getTimestamp() {
            return super.getTime() * 1000L;
        }

    }

    class TimestampDate {

        private LocalDateTime ldt;

        public TimestampDate(long date) {
            ldt = LocalDateTime.ofInstant(Instant.ofEpochMilli(date), ZoneId.of("UTC"));
        }

        public long getTimestamp() {
            return getTime();
        }

        public long getTime() {
            return ldt.atZone(ZoneId.of("UTC")).toInstant().toEpochMilli();
        }

        public LocalDateTime getLocalDateTime() {
            return ldt;
        }

        public void setTime(LocalDateTime ldt) {
            this.ldt = ldt;
        }

        public String toString() {
            if (ldt == null) {
                return "";
            }
            return DateTimeFormatter.RFC_1123_DATE_TIME.format(ldt.atZone(ZoneId.of("UTC")));
        }
    }


}