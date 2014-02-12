##! Implements base functionality for MySQL analysis. Generates the mysql.log file.

module MySQL;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:     time    &log;
		## Unique ID for the connection.
		uid:    string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:     conn_id &log;
	};

	## Event that can be handled to access the MySQL record as it is sent on
	## to the logging framework.
	global log_mysql: event(rec: Info);
}

const ports = { 3306/tcp };

event bro_init() &priority=5
	{
	Log::create_stream(MySQL::LOG, [$columns=Info, $ev=log_mysql]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_MYSQL, ports);
	}

# event mysql_event(c: connection)
# 	{
# 	local info: Info;
# 	info$ts  = network_time();
# 	info$uid = c$uid;
# 	info$id  = c$id;

# 	Log::write(MySQL::LOG, info);
# 	}

event mysql_handshake_response(c: connection, username: string)
	{
	print(username);
	}

