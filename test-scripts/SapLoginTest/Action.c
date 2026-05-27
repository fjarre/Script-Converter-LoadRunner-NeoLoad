#include "as_web.h"

Action()
{
    /* SAP GUI Login */
    sapgui_logon("{username}", "{password}", "{client}", "EN");
    
    lr_think_time(2);
    
    sapgui_select_active_window("wnd[0]");
    
    return 0;
}
