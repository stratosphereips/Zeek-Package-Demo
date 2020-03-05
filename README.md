# Zeek-Package-Demo

## Example 1: Running package from public repository

1. Install Zeek Package Manager:
```
pip install zkg
```
2. Choose package from public repository, e.g. mine
```
zkg install IRC-Zeek-package
```

3. Download example pcap: 2018-12-21-15-50-14-192.168.1.195.irc.pcap: 
```
wget --no-check-certificate https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/2018-12-21-15-50-14-192.168.1.195.irc.pcap
```
4. Run package on downloaded pcap: 
```
zeek IRC-Zeek-package -r 2018-12-21-15-50-14-192.168.1.195.irc.pcap
```
# Example 2: Create hello-world package

1. Create a git repository:
```
mkdir hello-world && cd hello-world && git init
```
2. Create a package metadata file, zkg.meta:
```
echo '[package]' > zkg.meta
```
3. Create a __load__.zeek script with example code in it:
```
echo 'event zeek_init() { print "hello world!"; }' > __load__.zeek
```
4. Commit everything to git:
```
git add * && git commit -m 'First commit'
```
5. (Optional) Test that Zeek correctly loads the script after installing the package with zkg:
```
zkg install .
zeek hello-world
zkg remove .
```

## Example 3: Create more useful package
Create a git repository:
```
mkdir irc-messages && cd irc-messages && git init
```
Create a package metadata file, zkg.meta:
```
echo '[package]' > zkg.meta
```

Create __load__.zeek script: 
echo '@load ./main > __load__.zeek

Create main.zeek file:
```
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
 ```
 
Commit everything to git:
```
git add * && git commit -m 'First commit'
```

(Optional) Test that Zeek correctly loads the script after installing the package with zkg:
```
zkg install .
zeek irc-messages -r 2018-12-21-15-50-14-192.168.1.195.irc.pcap
```
