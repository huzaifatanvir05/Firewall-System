/******************************************************************************************
                    ENTERPRISE STATEFUL FIREWALL
                PRODUCTION STYLE SINGLE FILE VERSION
-------------------------------------------------------------------------------------------
FEATURES:
1. Stateful TCP Inspection
2. UDP Session Tracking
3. ICMP Validation
4. Connection State Table
5. Rule Engine
6. Packet Validation
7. SYN Flood Protection
8. Logging System
9. Terminal Rule Management
10. Session Timeout Handling
11. Thread Safety
12. Real-Time Packet Processing Support
13. Compatible With Packet Sniffer
14. Windows Compatible Architecture
15. Designed For WinDivert/WFP Integration
-------------------------------------------------------------------------------------------
NOTE:
- This file is intentionally written in ONE FILE as requested.
- In real production, each section would be separated into multiple files.
- Your packet sniffer should call processPacket().
******************************************************************************************/




/******************************************************************************************
                                    LIBRARIES
******************************************************************************************/

#include<iostream>
#include<string>
#include<vector>
#include<unordered_map>
#include<fstream>
#include<mutex>
#include<algorithm>
#include<ctime>
#include<thread>
#include<chrono>

using namespace std;




/******************************************************************************************
                            PACKET INFORMATION STRUCTURE
******************************************************************************************/

struct PacketInfo
{
    string sourceIp;

    string destinationIp;

    string sourceMac;

    string destinationMac;

    int sourcePort;

    int destinationPort;

    string protocol;

    bool synFlag;

    bool ackFlag;

    bool finFlag;

    bool rstFlag;

    unsigned int sequenceNumber;

    unsigned int acknowledgementNumber;

    int ttl;

    int packetLength;

    string payload;
};




/******************************************************************************************
                                CONNECTION STATE ENTRY
******************************************************************************************/

struct ConnectionState
{
    string connectionKey;

    string protocol;

    string state;

    unsigned int sequenceNumber;

    unsigned int acknowledgementNumber;

    time_t lastSeen;
};




/******************************************************************************************
                                    FIREWALL LOGGER
******************************************************************************************/

class FirewallLogger
{
private:

    ofstream logFile;

    mutex logMutex;

public:

                                        //Constructor
    FirewallLogger()
    {
        logFile.open("enterprise_firewall_logs.txt",
                     ios::app);
    }

                                        //Write Log
    void writeLog(const string& message)
    {
        lock_guard<mutex> guard(logMutex);

        time_t now = time(0);

        string timestamp = ctime(&now);

        timestamp.pop_back();

        logFile<<"["<<timestamp<<"] "
               <<message
               <<endl;
    }

                                        //Destructor
    ~FirewallLogger()
    {
        logFile.close();
    }
};




/******************************************************************************************
                                    FIREWALL RULE
******************************************************************************************/

class FirewallRule
{
private:

    string ruleId;

    string protocol;

    string sourceIp;

    string sourceMac;

    int port;

    string action;

    int priority;

public:

                                        //Constructor
    FirewallRule(string id,
                 string proto,
                 string ip,
                 string mac,
                 int p,
                 string act,
                 int prio)
    {
        ruleId = id;

        protocol = proto;

        sourceIp = ip;

        sourceMac = mac;

        port = p;

        action = act;

        priority = prio;
    }

                                        //Get Priority
    int getPriority() const
    {
        return priority;
    }

                                        //Get Action
    string getAction() const
    {
        return action;
    }

                                        //Packet Matching
    bool matchesPacket(const PacketInfo& packet)
    {
        return packet.protocol == protocol &&
               packet.sourceIp == sourceIp &&
               packet.sourceMac == sourceMac &&
               packet.sourcePort == port;
    }
};




/******************************************************************************************
                                ENTERPRISE FIREWALL
******************************************************************************************/

class EnterpriseFirewall
{
private:

                                        //Rule Table
    vector<FirewallRule> ruleSet;

                                        //State Table
    unordered_map<string,
                  ConnectionState> stateTable;

                                        //Logger
    FirewallLogger logger;

                                        //Mutex
    mutex firewallMutex;

                                        //SYN Flood Tracking
    unordered_map<string, int> synCounter;

public:

/******************************************************************************************
                            GENERATE CONNECTION KEY
******************************************************************************************/

    string generateConnectionKey(
        const PacketInfo& packet)
    {
        return packet.sourceIp +
               ":" +
               to_string(packet.sourcePort) +
               "-" +
               packet.destinationIp +
               ":" +
               to_string(packet.destinationPort) +
               "-" +
               packet.protocol;
    }




/******************************************************************************************
                                ADD FIREWALL RULE
******************************************************************************************/

    void addRule(const FirewallRule& rule)
    {
        ruleSet.push_back(rule);

        sort(ruleSet.begin(),
             ruleSet.end(),

             [](FirewallRule a,
                FirewallRule b)
             {
                 return a.getPriority()
                      < b.getPriority();
             });

        logger.writeLog(
            "Firewall Rule Added."
        );
    }




/******************************************************************************************
                            CHECK EXISTING SESSION
******************************************************************************************/

    bool isKnownSession(
        const string& key)
    {
        return stateTable.find(key)
               != stateTable.end();
    }




/******************************************************************************************
                            REMOVE EXPIRED SESSIONS
******************************************************************************************/

    void cleanupExpiredSessions()
    {
        time_t currentTime =
        time(0);

        for(auto it = stateTable.begin();
            it != stateTable.end();)
        {
            if(difftime(currentTime,
                        it->second.lastSeen)
               > 120)
            {
                logger.writeLog(
                    "Session Expired : "
                    + it->first
                );

                it =
                stateTable.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }




/******************************************************************************************
                                BASIC VALIDATIONS
******************************************************************************************/

                                        //IP Validation
    bool validateIPAddress(
        const PacketInfo& packet)
    {
        if(packet.sourceIp.empty() ||
           packet.destinationIp.empty())
        {
            logger.writeLog(
                "Invalid IP Address."
            );

            return false;
        }

        return true;
    }

                                        //MAC Validation
    bool validateMACAddress(
        const PacketInfo& packet)
    {
        if(packet.sourceMac.empty() ||
           packet.destinationMac.empty())
        {
            logger.writeLog(
                "Invalid MAC Address."
            );

            return false;
        }

        return true;
    }

                                        //TTL Validation
    bool validateTTL(
        const PacketInfo& packet)
    {
        if(packet.ttl <= 0)
        {
            logger.writeLog(
                "Invalid TTL."
            );

            return false;
        }

        return true;
    }

                                        //Packet Length Validation
    bool validatePacketLength(
        const PacketInfo& packet)
    {
        if(packet.packetLength <= 0 ||
           packet.packetLength > 65535)
        {
            logger.writeLog(
                "Invalid Packet Length."
            );

            return false;
        }

        return true;
    }




/******************************************************************************************
                                RULE VALIDATION
******************************************************************************************/

    bool validateRules(
        const PacketInfo& packet)
    {
        for(FirewallRule& rule : ruleSet)
        {
            if(rule.matchesPacket(packet))
            {
                if(rule.getAction() == "BLOCK")
                {
                    logger.writeLog(
                        "Packet Blocked By Rule."
                    );

                    return false;
                }

                return true;
            }
        }

        return true;
    }




/******************************************************************************************
                                TCP VALIDATION
******************************************************************************************/

    bool validateTCPPacket(
        const PacketInfo& packet)
    {
                                        //Invalid Ports
        if(packet.sourcePort <= 0 ||
           packet.destinationPort <= 0)
        {
            logger.writeLog(
                "Invalid TCP Ports."
            );

            return false;
        }

                                        //Invalid Flags
        if(packet.synFlag &&
           packet.finFlag)
        {
            logger.writeLog(
                "Invalid TCP Flags."
            );

            return false;
        }

                                        //RST Validation
        if(packet.rstFlag &&
           packet.sequenceNumber == 0)
        {
            logger.writeLog(
                "Invalid TCP Reset Packet."
            );

            return false;
        }

                                        //SYN Flood Protection
        if(packet.synFlag &&
           !packet.ackFlag)
        {
            synCounter[packet.sourceIp]++;

            if(synCounter[packet.sourceIp]
               > 100)
            {
                logger.writeLog(
                    "Possible SYN Flood Attack."
                );

                return false;
            }
        }

                                        //Known Session
        string key =
        generateConnectionKey(packet);

        if(isKnownSession(key))
        {
            stateTable[key].lastSeen =
            time(0);

            return true;
        }

                                        //New TCP Session
        if(packet.synFlag &&
           !packet.ackFlag)
        {
            ConnectionState session;

            session.connectionKey =
            key;

            session.protocol =
            "TCP";

            session.state =
            "SYN_SENT";

            session.sequenceNumber =
            packet.sequenceNumber;

            session.acknowledgementNumber =
            packet.acknowledgementNumber;

            session.lastSeen =
            time(0);

            stateTable[key] =
            session;

            logger.writeLog(
                "TCP Session Created."
            );

            return true;
        }

                                        //Unauthorized TCP Packet
        logger.writeLog(
            "Unauthorized TCP Packet."
        );

        return false;
    }




/******************************************************************************************
                                UDP VALIDATION
******************************************************************************************/

    bool validateUDPPacket(
        const PacketInfo& packet)
    {
                                        //Port Validation
        if(packet.sourcePort <= 0 ||
           packet.destinationPort <= 0)
        {
            logger.writeLog(
                "Invalid UDP Ports."
            );

            return false;
        }

                                        //UDP Flood Protection
        if(packet.packetLength > 4096)
        {
            logger.writeLog(
                "Possible UDP Flood."
            );

            return false;
        }

                                        //Known Session
        string key =
        generateConnectionKey(packet);

        if(isKnownSession(key))
        {
            stateTable[key].lastSeen =
            time(0);

            return true;
        }

                                        //Create UDP Session
        ConnectionState session;

        session.connectionKey =
        key;

        session.protocol =
        "UDP";

        session.state =
        "UDP_ACTIVE";

        session.sequenceNumber =
        0;

        session.acknowledgementNumber =
        0;

        session.lastSeen =
        time(0);

        stateTable[key] =
        session;

        logger.writeLog(
            "UDP Session Created."
        );

        return true;
    }




/******************************************************************************************
                                ICMP VALIDATION
******************************************************************************************/

    bool validateICMPPacket(
        const PacketInfo& packet)
    {
                                        //Oversized ICMP Protection
        if(packet.packetLength > 2048)
        {
            logger.writeLog(
                "Suspicious ICMP Packet."
            );

            return false;
        }

                                        //Known Session
        string key =
        generateConnectionKey(packet);

        if(isKnownSession(key))
        {
            stateTable[key].lastSeen =
            time(0);

            return true;
        }

                                        //Create ICMP Session
        ConnectionState session;

        session.connectionKey =
        key;

        session.protocol =
        "ICMP";

        session.state =
        "ICMP_ACTIVE";

        session.sequenceNumber =
        0;

        session.acknowledgementNumber =
        0;

        session.lastSeen =
        time(0);

        stateTable[key] =
        session;

        logger.writeLog(
            "ICMP Session Created."
        );

        return true;
    }




/******************************************************************************************
                            MAIN PACKET PROCESSOR
******************************************************************************************/

    bool processPacket(
        const PacketInfo& packet)
    {
        lock_guard<mutex> guard(
            firewallMutex
        );

                                        //Cleanup Sessions
        cleanupExpiredSessions();

                                        //Basic Validations
        if(!validateIPAddress(packet))
        {
            return false;
        }

        if(!validateMACAddress(packet))
        {
            return false;
        }

        if(!validateTTL(packet))
        {
            return false;
        }

        if(!validatePacketLength(packet))
        {
            return false;
        }

                                        //Rule Validation
        if(!validateRules(packet))
        {
            return false;
        }

                                        //Protocol Handling
        bool allowed = false;

        if(packet.protocol == "TCP")
        {
            allowed =
            validateTCPPacket(packet);
        }

        else if(packet.protocol == "UDP")
        {
            allowed =
            validateUDPPacket(packet);
        }

        else if(packet.protocol == "ICMP")
        {
            allowed =
            validateICMPPacket(packet);
        }

        else
        {
            logger.writeLog(
                "Unsupported Protocol."
            );

            return false;
        }

                                        //Final Logging
        if(allowed)
        {
            logger.writeLog(
                "Packet Allowed : "
                + generateConnectionKey(packet)
            );
        }
        else
        {
            logger.writeLog(
                "Packet Blocked : "
                + generateConnectionKey(packet)
            );
        }

        return allowed;
    }




/******************************************************************************************
                            TERMINAL RULE INPUT
******************************************************************************************/

    void terminalRuleInput()
    {
        string id;

        string protocol;

        string ip;

        string mac;

        int port;

        string action;

        int priority;

        cout<<"\n========== ADD FIREWALL RULE =========="
            <<endl;

        cout<<"Rule ID : ";
        cin>>id;

        cout<<"Protocol(TCP/UDP/ICMP) : ";
        cin>>protocol;

        cout<<"Source IP : ";
        cin>>ip;

        cout<<"Source MAC : ";
        cin>>mac;

        cout<<"Port : ";
        cin>>port;

        cout<<"Action(ALLOW/BLOCK) : ";
        cin>>action;

        cout<<"Priority : ";
        cin>>priority;

        FirewallRule rule(
            id,
            protocol,
            ip,
            mac,
            port,
            action,
            priority
        );

        addRule(rule);

        logger.writeLog(
            "Rule Added Through Terminal."
        );
    }




/******************************************************************************************
                            FIREWALL CONSOLE
******************************************************************************************/

    void firewallConsole()
    {
        int choice;

        while(true)
        {
            cout<<"\n========== ENTERPRISE FIREWALL =========="
                <<endl;

            cout<<"1. Add Rule"<<endl;

            cout<<"2. Exit"<<endl;

            cout<<"Choice : ";

            cin>>choice;

            switch(choice)
            {
                case 1:

                    terminalRuleInput();

                    break;

                case 2:

                    return;

                default:

                    cout<<"Invalid Choice."
                        <<endl;
            }
        }
    }
};




/******************************************************************************************
                                    INTEGRATION
******************************************************************************************/

/*
YOUR PACKET SNIFFER SHOULD CALL:

EnterpriseFirewall firewall;

firewall.processPacket(packet);

WHERE packet IS PacketInfo STRUCTURE.

EXAMPLE:

PacketInfo packet;

packet.sourceIp = "192.168.1.5";

packet.destinationIp = "8.8.8.8";

packet.protocol = "TCP";

packet.synFlag = true;

firewall.processPacket(packet);

*/