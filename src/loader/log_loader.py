import csv
import json
import logging
from optparse import OptionParser
import os
from unittest import TestCase, TestLoader, TestSuite, TextTestRunner
import unittest
import urllib2
from datetime import datetime


logger = logging.getLogger('LogDataLoader')
logger.setLevel(logging.DEBUG)

FORMAT = logging.Formatter('%(asctime)s %(name)s %(funcName)s %(lineno)d %(levelname)s: %(message)s')

ch = logging.StreamHandler() # logging.FileHandler('loader.log')
ch.setLevel(logging.DEBUG)
ch.setFormatter(FORMAT)

logger.addHandler(ch)


#---------------------------------------------------------------------------
# Base classes
#---------------------------------------------------------------------------
class BaseReaderBreaker:
    def breakFromThisLine(self, lineIndex, lineNum, totalReadLineCount, lineContent):
        return False


class BaseLineFormatter:
    def format(self, lineContent):
        return lineContent


class BaseLogLineFilter:
    def accept(self, lineContent):
        return True


class LastAcceptedReaderBreaker(BaseReaderBreaker):
    def breakFromThisLine(self, lineIndex, lineNum, totalReadLineCount, lineContent):
        return totalReadLineCount > 0


class BaseLogDataLoader:
    """Base loader class to read log files
    """

    def load(self, filePath):
        return self._get_last_data(filePath)

    #---------------------------------------------------------------------------
    #   protected functions
    #---------------------------------------------------------------------------
    def _get_data_from_file(self, filePath, lineFormatter=None, logLineFilters=None, readerBreaker=None):
        """The main function used to read data
        @:param serverLogDataPath the absolute file path to the log file, if not exist, the result will be None
        @:param lineFormatter reformat the line, leave only things you wanted.
                if not given, the entire line will be appended to list
        @:param logFilters, a list contains filters to filter log lines
                a filter should have a function called "accept" with one parameter: lineContent
                lineContent is the formatted content
                if not given, all lines will be appended to list
        @:param readerBreaker, an instance used to break the reader, say if there are too many lines.
                should have a function called "breakFromThisLine" with the following parameters:
                lineIndex, lineNum, totalReadLineCount, lineContent
        @:see class ServerLogFilter about how to write a filter
        @seeAlso class ServerLogReaderBreaker to see how to break the reading
        @:return a list contains wanted data
        """

        # if the given path does not exist, just return None,
        if not os.path.isfile(filePath):
            logger.error('The given path to server log data file does not exist! ')
            logger.error('  The given path:\n %s ' % filePath)
            return None

        return self.__read_data_from_file(filePath, lineFormatter, logLineFilters, readerBreaker)

    def _get_last_data(self, serverLogDataPath, lineFormatter=None, logLineFilters=None):
        return self._get_data_from_file(serverLogDataPath, lineFormatter, logLineFilters, LastAcceptedReaderBreaker())

    def _get_line_delimiter(self):
        return ' '

    def _get_file_quote(self):
        return '"'

    #---------------------------------------------------------------------------
    #   private functions
    #---------------------------------------------------------------------------

    def __read_data_from_file(self, filePath, lineFormatter=None, filters=None, readerBreaker=None):
        rst_lines = []
        line_index = 0

        with open(filePath, 'rb') as f:
            csvReader = csv.reader(f, delimiter=self._get_line_delimiter(), quotechar=self._get_file_quote())
            lines = list(csvReader)
            line_count = len(lines)
            for line in reversed(lines):  # read from the last line
                line_index += 1

                if len(line) == 0:
                    continue

                data = line
                if not lineFormatter is None:
                    data = lineFormatter.format(line)                # break from the current line

                if not readerBreaker is None:
                    if readerBreaker.breakFromThisLine(line_index, line_count - line_index, len(rst_lines), data):
                        logger.info('Reader break from line %d' % line_index)
                        break

                line_accepted = True

                # filter line, only accepted
                if not filters is None:
                    for fi in filters:
                        line_accepted = fi.accept(data)
                        if not line_accepted:
                            break

                if not line_accepted:
                    continue

                rst_lines.append(data)

        return rst_lines

    def __format_data(self, data):
        cols = data.split('&')

        kvList = {}
        for col in cols:
            kv = col.split('=')

            kvList[kv[0]] = urllib2.unquote(kv[1])

        return kvList


#---------------------------------------------------------------------------
# Server Data loader
#---------------------------------------------------------------------------
class ServerLogFormatter(BaseLineFormatter):
    def format(self, lineContent):
        cols = lineContent  # shlex.split(lineContent)

        d = self.__create_empty_dict()

        if len(cols) == 10:
            d['ip'] = cols[0]
            d['datetime'] = datetime.strptime(cols[1], '%Y-%m-%dT%H:%M:%S+08:00')
            d['method'] = cols[2]
            d['data'] = self.__format_data_field(cols[5])
            d['return_code'] = cols[6]
            d['user_agent'] = cols[9]  # self.__format_device_info(cols[9])
            #logger.debug("Formatted server data:")
            #logger.debug(d)

        return d

    def __create_empty_dict(self):
        return {'ip': '',
                'datetime': '',
                'method': '',
                'data': '',
                'return_code': '',
                'user_agent': ''}

    def __format_data_field(self, data):
        if data == '-':
            return ''

        tmpData = urllib2.unquote(data)

        cols = tmpData.split('&')
        #logger.debug('Data field looks like this: \n %s' % tmpData)

        kvList = {}
        for col in cols:
            kv = col.split('=')
            kvList[kv[0]] = kv[1]

        return kvList

    def __format_device_info(self, device):
        cols = device.split(';')
        return cols


class ServerDataFilter(BaseLogLineFilter):
    def __init__(self, pid, userAgent, jsonDataStr):
        self.pid = pid
        self.userAgent = userAgent
        self.jsonData = jsonDataStr

    def accept(self, lineContent):
        # log contains no data information
        if lineContent['data'] == '':
            return False

        # pid is not the wanted one
        if not 'p' in lineContent['data']:
            return False
        if self.pid != lineContent['data']['p']:
            return False

        # if userAgent is given, see the log has the same value
        if self.userAgent is not None:
            if lineContent['user_agent'] != self.userAgent:
                return False

        # json data has to be the same as the client log
        #if self.jsonData != lineContent['data']['s']:
        #    return False

        return True


class ServerLogTimeLastBreaker(BaseReaderBreaker):
    def __init__(self, startTime, endTime=None):
        self.startTime = startTime
        self.endTime = endTime

    def breakFromThisLine(self, lineIndex, lineNum, totalReadLineCount, lineContent):
        if self.startTime > lineContent['datetime']:
            return True

        if self.endTime is not None:
            if self.endTime < lineContent['datetime']:
                return True

        return False


class ServerDataLoader(BaseLogDataLoader):
    """A class used to read and filter server log data file"""

    def __init__(self, pid, userAgent, jsonDataStr, sendTime):
        self.pid = pid
        self.user_agent = userAgent
        self.jsonStr = jsonDataStr
        self.startTime = sendTime

    def load(self, serverLogDataPath):
        formatter = ServerLogFormatter()
        filters = [ServerDataFilter(self.pid, self.user_agent, self.jsonStr), ]
        breaker = ServerLogTimeLastBreaker(self.startTime)

        return self._get_data_from_file(serverLogDataPath, formatter, filters, breaker)


#---------------------------------------------------------------------------
# Local Data loader
#---------------------------------------------------------------------------
class LocalLogFormatter(BaseLineFormatter):
    def __create_empty_dict(self):
        return {'datetime': '',
                'user_agent': '',
                'data': ''}

    def format(self, lineContent):
        #logger.debug("Local data line: %s" % lineContent)

        d = self.__create_empty_dict()

        if len(lineContent) == 3:
            d['datetime'] = datetime.strptime(lineContent[0], '%Y-%m-%d %H:%M:%S')
            d['user_agent'] = lineContent[1]
            d['data'] = lineContent[2]

        return d

        def __format_ua(self, ua):
            return ua.split(':')[1]


class LocalDataFileLoader(BaseLogDataLoader):
    def load(self, filePath):
        return self._get_last_data(filePath, LocalLogFormatter(), None)

    def _get_line_delimiter(self):
        return '\t'


#---------------------------------------------------------------------------
# Output utils
#---------------------------------------------------------------------------
class MyCsvWriter:
    def write_to_csv(self, path, full_data):
        csvWriter = None
        with open(path, 'wb') as f:
            for data in full_data:
                if csvWriter is None:
                    fields = [field for field in data.keys()]
                    csvWriter = csv.DictWriter(f, fieldnames=fields, delimiter=',', quotechar='"')

                csvWriter.writerow(data)


class TestData(TestCase):
    @classmethod
    def setUpClass(cls):
        """This function used to load fixtures for all test cases.
        include but not limited:
           ##fixtures directory path
           ##configurations stored in config file
           ##last line of local log

"""
        # use a directory called fixtures to store all test required files and data

        cls._fixtures = os.path.join(os.path.dirname(__file__), 'fixtures')

        # use a configuration file to store all changeable variables
        # for instance, paths to the log files
        cfg_file_path = os.path.join(cls._fixtures, 'test.cfg')

        cfg = ConfigLoader()
        cfg.load(cfg_file_path)
        cls._cfg = cfg

        localDataLoader = LocalDataFileLoader()
        cls._data = localDataLoader.load(cfg.localLogInputPath)[0]
        logger.debug('local data loaded: ')
        logger.debug(cls._data)

        logger.debug('local json data formatted: ')
        logger.debug('\n' + json.dumps(json.loads(cls._data['data'], encoding='utf8'), indent=4, separators=(',', ':')))

    def test_server_data(self):
        """
        Test if the local log has been sent to server.
        If sent, there should be one and only one log been found

        """
        loader = ServerDataLoader("e7a564d6b1d6e03e", self._data['user_agent'], self._data['data'], self._data['datetime'])
        full_data = loader.load(self._cfg.serverLogInputPath)
        logger.debug('Server log data loaded: ')
        logger.debug(full_data)
        self.assertIsNotNone(full_data)

        length = len(full_data)
        self.assertEqual(1, length, 'There should be one and one only data been found.')
        self.assertEqual(self._data['data'], full_data[-1]['data']['s'], 'Local data should be the same as server json data')

        logger.debug("Server json data:")
        logger.debug(full_data[0]['data']['s'])
        logger.debug("Formatted server json data:")
        logger.debug('\n' + json.dumps(json.loads(full_data[0]['data']['s'], encoding='utf8'), indent=4, separators=(',', ':')))


    def __has_event(self, events, eventName):
        for e in events:
            if e['t1'] == eventName:
                self.assertEqual(e['n1'], '3G', 'n1 should be WIFI')
                return True

        return False

    @unittest.skip("concentrate on another test case")
    def test_local_data(self):
        """
        Main test function used to validate the output log is correct

        """
        jsonData = json.loads(self._data['data'], encoding='utf8')

        self.assertIsNotNone(jsonData)

        logger.debug('local json data formatted: ')
        logger.debug('\n' + json.dumps(jsonData, indent=4, separators=(',', ':')))

        #events = jsonData['b']['a']
        #self.assertTrue(self.__has_event(events, 'A1006'))



        # def test_server_json(self):
        #     loader = ServerDataLoader("e7a564d6b1d6e03e", '-')
        #     full_data = loader.load("/Users/Pamela/Dropbox/public/data.log")
        #
        #     with open("/Users/Pamela/Desktop/server_data.txt", 'w') as f:
        #         for data in full_data:
        #             logger.debug(data["data"]['s'])
        #             utf_data = data["data"]['s']
        #             f.write(json.dumps(json.loads(utf_data), indent=4, separators=(',', ':')))

#---------------------------------------------------------------------------
# Executable codes
#---------------------------------------------------------------------------


class ConfigLoader:
    serverLogInputPath = 'server_input.log'
    serverLogPID = 'e7a564d6b1d6e03e'
    serverLogDeviceName = None
    serverLogOutputPath = 'server_output.txt'
    localLogInputPath = 'local_input.log'
    localLogOutputPath = 'local_output.txt'

    def load(self, path):
        try:
            import ConfigParser

            config = ConfigParser.ConfigParser()
            config.readfp(open(path))

            self.serverLogInputPath = self.__normalize_path(config.get('Server', 'input'))
            self.serverLogPID = config.get('Server', 'pid')
            self.serverLogDeviceName = config.get('Server', 'device', None)
            self.serverLogOutputPath = self.__normalize_path(config.get('Server', 'output'))
            self.localLogInputPath = self.__normalize_path(config.get('Local', 'input'))
            self.localLogOutputPath = self.__normalize_path(config.get('Local', 'output'))
        except Exception as ex:
            logger.error("Something goes wrong with the config file: %s" % ex.message)

    def __normalize_path(self, path):
        return os.path.abspath(os.path.expanduser(path))


if __name__ == "__main__":
    loader = TestLoader()
    suite = TestSuite((
        loader.loadTestsFromTestCase(TestData),
    ))

    runner = TextTestRunner(verbosity=2)
    runner.run(suite)


# usage = '''\
# python log_loader.py [options]
#
# Read and analyze log file from both server part and local, and output formatted
# data to a file.
# Simply run this script in a directory containing a LogLoader.cfg, or use -c to
# give a path to the config file.
# '''
#
# parser = OptionParser(usage=usage)
# parser.add_option("-c", None, action="store", dest="config_file",
#                   help=("Specify the path to the file path configuration "
#                         "file to be used."))
#
# options, args = parser.parse_args()
#
# config_file_path = 'LogLoader.cfg'
#
# # if -c was provided, we use it to find config file
# if options.config_file is not None:
#     config_file_path = os.path.abspath(os.path.expanduser(options.config_file))
#
# cfg = ConfigLoader()
# cfg.load(config_file_path)
#
# csvWriter = MyCsvWriter()
#
# localLoader = LocalDataFileLoader()
# localFullData = localLoader.load(cfg.localLogInputPath)
# csvWriter.write_to_csv(cfg.localLogOutputPath, localFullData)
#
# serverLoader = ServerDataLoader(cfg.serverLogPID, cfg.serverLogDeviceName, localFullData[0]['data'],
#                                 localFullData[0]['datetime'])
# serverFullData = serverLoader.load(cfg.serverLogInputPath)
# csvWriter.write_to_csv(cfg.serverLogOutputPath, serverFullData)
