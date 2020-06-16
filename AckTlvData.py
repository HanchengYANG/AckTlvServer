import ipaddress
from datetime import datetime as datetime
import numpy as np
import matplotlib.pyplot as plt


class AckProduct:

    class AckAp:
        def __init__(self, mac_addr):
            self.__mac = mac_addr
            self.__time = list()
            self.__sig = list()

        def add_signal_value(self, dt: datetime, sig: int):
            self.__time.append(dt)
            self.__sig.append(sig)

        def plot(self, ax: plt.Axes):
            ax.plot(np.array(self.__time), np.array(self.__sig), label='%s' % self.__mac)

    def __init__(self, ip_str: str, dt: datetime):
        self.__ip = int(ipaddress.IPv4Address(ip_str))
        self.__aps = dict()
        self.__ol_dt_l = list([dt])

    def online(self, dt: datetime):
        self.__ol_dt_l.append(dt)

    def add_scan_res(self, mac_addr, dt: datetime, sig: int):
        if mac_addr not in self.__aps.keys():
            self.__aps[mac_addr] = AckProduct.AckAp(mac_addr)
        self.__aps[mac_addr].add_signal_value(dt, sig)
        self.plot()

    def plot(self):
        fig, ax = plt.subplots()
        for ap in self.__aps.values():
            ap.plot(ax)
        ax.set_xlabel("Time")
        ax.set_ylabel("Signal level in dBm")
        ax.set_title("Scan result of %s" % str(ipaddress.IPv4Address(self.__ip)))
        ax.set_ylim([-80, 0])
        ax.legend()
        fig.savefig('./plot.png')
        plt.close(fig)


class AckServerDatabase:

    def __init__(self):
        self.__prods = dict()

    def product_online(self, ip_str: str, dt: datetime):
        ip = int(ipaddress.IPv4Address(ip_str))
        if ip not in self.__prods.keys():
            self.__prods[ip] = AckProduct(ip_str, dt)
        else:
            self.__prods[ip].online(dt)

    def get_product(self, ip_str: str):
        return self.__prods.get(int(ipaddress.IPv4Address(ip_str)), None)


AckTlvDB = AckServerDatabase()
