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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.time.DayOfWeek;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
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
        if (invocation.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
            return null;
        }

        ArrayList menu = new ArrayList();
        JMenuItem item = new JMenuItem("Edit timestamp");
        item.addActionListener(this);

        if (extractTimestamp(invocation) != null) {
            this.invocation = invocation;
            item.setEnabled(true);
        } else {
            item.setEnabled(false);
        }
        menu.add(item);
        return menu;

    }

    private TimestampDate extractTimestamp(IContextMenuInvocation invocation) {
        int[] bounds = invocation.getSelectionBounds();
        byte[] request = invocation.getSelectedMessages()[0].getRequest();
        String message = Utilities.helpers.bytesToString(request);
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
            return null;
        }
    }

    @Override
    public void actionPerformed(ActionEvent evt) {
        if (invocation == null) {
            return;
        }

        TimestampDate date = extractTimestamp(invocation);
        Utilities.debug("Date: " + date.toString());
        Utilities.debug("LDT: " + date.toInstant().atZone(ZoneId.of("UTC")).toLocalDateTime());

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
        picker.setDateTimeStrict(date.toInstant().atZone(ZoneId.of("UTC")).toLocalDateTime());

        int results = JOptionPane.showConfirmDialog(
                null,
                new JScrollPane(picker),
                "Choose Date/Time",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );

        if (results == JOptionPane.OK_OPTION) {
            date.setTime(picker.getDateTimeStrict().atZone(ZoneId.of("UTC")).toEpochSecond() * 1000L);
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

    class TimestampDate extends Date {

        public TimestampDate(long date) {
            super(date);
        }

        public long getTimestamp() {
            return super.getTime();
        }

    }


}