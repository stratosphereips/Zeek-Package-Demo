@load base/bif/plugins/Zeek_IRC.events.bif.zeek

module TOM;

type IRC_Record: record {
    msg: string &log;
};

export {
    redef enum Log::ID += { LOG };
    
    global log_irc_session: event(rec: IRC_Record);
}


global irc_records: vector of IRC_Record = vector();

# uncomment to use JSON as output
# redef LogAscii::use_json = T;

event zeek_init()
{
    Log::create_stream(TOM::LOG, [$columns=IRC_Record, $path="irc_records"]);
}

event irc_privmsg_message(c: connection, is_orig: bool, source: string, target: string, message: string) {
    local ev: IRC_Record = IRC_Record($msg=message);
    irc_records += ev;
}

event zeek_done()
{
    for (i in irc_records) {
        Log::write( TOM::LOG, irc_records[i]);
    }
}