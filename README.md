Provides a GUI to edit Unix timestamps in Burp message editors.

Select the timestamp, then right-click and choose "Edit Timestamp". 
It can handle timestamps in seconds, milliseconds, and microseconds 
(although the UI reverts this to 0 milli/microseconds).

The menu item will be disabled if the selected value cannot be parsed 
as a timestamp. If it can be parsed, there is also a tooltip on the 
menu item showing the date, for a quick conversion.

#### Context menu
![](screens/ss1.png)

#### Date picker
![](screens/ss2.png)

#### Tooltip
![](screens/ss3.png) 


_This extension uses the [LGoodDatePicker](https://github.com/LGoodDatePicker/LGoodDatePicker) 
library._