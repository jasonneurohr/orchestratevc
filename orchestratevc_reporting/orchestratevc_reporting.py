import requests
from json import loads, dumps
from datetime import datetime, timedelta, date
from collections import OrderedDict
from calendar import monthrange
import numpy as np
import pandas as pd
from pandas import Series, DataFrame


class CdrReport():
    def __init__(self, start_dt, end_dt, interval, url):
        self.start_dt = datetime.strptime(start_dt, '%Y%m%d')  # convert to datetime
        self.end_dt = datetime.strptime(end_dt, '%Y%m%d')  # convert to datetime
        self.url = url
        self.interval = interval
        self.filter_and_dps = OrderedDict()  # the filter and datapoint matrix dict
        self.parse_dict = {}
        self.record_list = []  # store for the retrieved CDRs
        self.create_filter_data_points(interval)  # create the filter and data points

    def create_filter_data_points(self, interval):
        """
        TODO
        """
        start = self.start_dt
        end = self.end_dt + timedelta(hours=23,minutes=59,seconds=59)
        count = 0

        while start < end:  # create the dict based on the interval
            # format {n:[filter_end, datapoint, datapoint count]}
            self.filter_and_dps[count] = [start + timedelta(minutes=interval), start, 0]
            start = start + timedelta(minutes=interval)
            count += 1
        
    def get_concurrent_conf_report(self, serial):
        """
        TODO
        """

        api_params = 'ciscoCdrTps?where={"$or":[{"event_type":"conferenceFinished"}, {"event_type":"conferenceStarted"}],' \
                    ' "time_stamp": {"$gt": "%s", "$lt":"%s"},"device_serial":"%s"}&sort=-time_stamp' % (
                        self.start_dt.strftime('%a, %d %b %Y %H:%M:%S GMT'),
                        self.end_dt.strftime('%a, %d %b %Y 23:59:59 GMT'),
                        serial)

        url = self.url + api_params
        self.query_api(url)
        self.parse_records()
        
    def results_json(self):
        """
        TODO
        """
        results = OrderedDict()

        for x,y in self.filter_and_dps.items():
            results[str(y[1])] = y[2]
        return dumps(results)

    def results_csv(self, path):
        """
        TODO
        """
        columns = []  # columns based on shorthand date by day
        index = []  # index based on the interval times
        points = []
        days = OrderedDict()  # days is a dict with key of short hand day, and value of list of datapoints
        morning = datetime.strptime('00:00:00', '%H:%M:%S')
        evening = datetime.strptime('23:59:59', '%H:%M:%S')
        while morning < evening:
            index.append(morning.strftime('%H:%M:%S'))
            morning = morning + timedelta(minutes=self.interval)

        start = self.start_dt
        end = self.end_dt

        while start < end:
            columns.append(start.strftime('%d/%m/%y'))
            start = start + timedelta(days=1)

        for day in columns:
            for k,v in self.filter_and_dps.items():
                dt = v[1].strftime('%Y-%d-%m %H:%M:%S')
                dt = datetime.strptime(dt,'%Y-%d-%m %H:%M:%S').strftime('%d/%m/%y')
                if dt == day:
                    points.append(v[2])
            days[day] = points
            points = []
  
        df = DataFrame(data=days, index=index, columns=columns)  # dataframe of the results
        df.to_csv(path)  # write the dataframe to csv file denoted by 'path'

    def query_api(self, url):
        """
        TODO
        """
        headers = {'Accepts': 'application/json'}
        session = requests.session()
        host_data = session.get(url, headers=headers)
        host_data = loads(host_data.text)

        if host_data['_meta']['total'] == 0:  # no records - stop here if true
            return

        for record in host_data['_items']:  # iterate through the records
            self.record_list.append(record)

        if 'next' in host_data['_links']:  # more records - update URL with next page and call query_api again
            self.query_api(self.url + str(host_data['_links']['next']['href']))

        elif 'next' not in host_data['_links']:  # no more records
            return
        return

    def parse_records(self):
        """
        TODO
        """
        conf_start_dict = {}  # dict for holding the conferenceStarted data k=conf_guid v=time_stamp
        for record in self.record_list:  
            if record['event_type'] == 'conferenceStarted':
                conf_start_dict[record['conference_guid']] = record['time_stamp']
        for record in self.record_list:  
            if record['event_type'] == 'conferenceFinished':
                if record['conference_guid'] in conf_start_dict:  # check there is a matching start event
                    guid = record['conference_guid']
                    # create an entry in the parse_dict with a guid as the key and a tuple of the start,end
                    self.parse_dict[record['conference_guid']] = ((conf_start_dict[guid]), record['time_stamp'])
        # now iterate the parse_dict and count the entries that fall over the datapoints
        for k,v in self.parse_dict.items():
            start,end = v
            start = datetime.strptime(start, '%a, %d %b %Y %H:%M:%S GMT')
            end = datetime.strptime(end, '%a, %d %b %Y %H:%M:%S GMT')

            x = 0
            while x <= len(self.filter_and_dps) - 1:
                # for every data point where the conf start time <= data point and
                # the conf end time is >= the data point. increment the datapoint counter
                # as this conf counts as concurrent  
                if start <= self.filter_and_dps[x][0] and end >= self.filter_and_dps[x][0]:
                    self.filter_and_dps[x][2] += 1
                x += 1
        return