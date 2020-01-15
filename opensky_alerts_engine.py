import logging
from sys import stdout

formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler = logging.StreamHandler(stdout)
console_handler.setFormatter(formatter)

internal_logger = logging.getLogger('opensky.alerts_engine')
internal_logger.addHandler(console_handler)
internal_logger.setLevel('INFO')


from enum import IntEnum
from datetime import datetime
import types
import mysql.connector


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    def __str__(self):
        return str.capitalize(self.name)
    
    def __repr__(self):
        return self.__str__()
    
    
class OpenSkyAlert:
    def __init__(self, severity: Severity, message: str, alert_time: datetime = None, source: str = 'NotDefined'):
        self._severity = severity
        self._message = message
        self._timestamp = alert_time if alert_time is not None else datetime.now()
        self._source = source
        
    @property
    def severity(self):
        return self._severity
    
    @property
    def message(self):
        return self._message
    
    @property
    def alert_time(self):
        return self._timestamp
    
    @property
    def source(self):
        return self._source

class BaseAlertsSender:
    def __init__(self, name):
        self._name = type(self)
        
    @property
    def name(self):
        return self._name

    def send(self, alert: OpenSkyAlert):
        raise NotImplemented

    @staticmethod
    def alert_message_builder(severity: Severity, message: str, alert_time: datetime = None) -> str:
        time = alert_time if alert_time is not None else datetime.now()
        return f'{time} : Alert of severity {str(severity)} occured : {message}'

    
class ConsoleAlertsSender(BaseAlertsSender):
    def __init__(self):
        super().__init__(self)
        
    @property
    def name(self):
        return self._name
    
    def send(self, alert: OpenSkyAlert):
        print(super().alert_message_builder(alert.severity, alert.message))
        return True

    
class OpenSkyAlertsEngine:
    def __init__(self, severity_threshold = Severity.MEDIUM):
        self.min_severity = severity_threshold
        self._active_rules = []
        self._active_senders = []
        
    @property
    def active_rules(self):
        return self._active_rules
    
    @property
    def active_senders(self):
        return self._active_senders
    
    def add_alerts_sender(self, alerts_sender:BaseAlertsSender):
        self._active_senders.append(alerts_sender)
         
    def add_rule(self, rule:types.FunctionType):
        self._active_rules.append(rule)
    
    def handle_row(self, row):
        for rule in self.active_rules:
            try:
                alert = rule(row)
                if alert != None:
                    if alert.severity >= self.min_severity:
                        for sender in self.active_senders:
                            sender.send(alert)
            except Exception as ex:
                internal_logger.error(f'at handle_row: {ex}')
                

class OpenSkySqlAlertsSender(BaseAlertsSender):
    def __init__(self, host, user, passwd, database, table):
        super().__init__(self)
        self.host = host
        self.user = user
        self.passwd = passwd
        self.database = database
        self.table = table
        self._connection = mysql.connector.connect(host=host, user=user, passwd=passwd,
                                                   database=database, autocommit=True)
        crsr = self._connection.cursor()
        create_alerts_table = (f"""CREATE TABLE IF NOT EXISTS {table} (timestamp TIMESTAMP, source_rule NVARCHAR(255), 
                                severity NVARCHAR(16), message longtext)""")
        crsr.execute(create_alerts_table)
        internal_logger.debug(f'Alerts sender initialized, with table : {table}')
        crsr.close()

    @property
    def mysql_connection(self):
        return self._connection
        
    def send(self, alert: OpenSkyAlert):
        crsr = self._connection.cursor()
        insert_alert = f"""INSERT INTO {self.table} 
                            (timestamp, source_rule, severity, message) 
                            VALUES 
                            ('{alert.alert_time}', '{alert.source}', '{str(alert.severity)}', "{alert.message}")
                            ;
                        """
        try:
            crsr.execute(insert_alert)
        except Exception as ex:
            internal_logger.error(f'error inserting alert into mysql : {ex}')
        crsr.close()


