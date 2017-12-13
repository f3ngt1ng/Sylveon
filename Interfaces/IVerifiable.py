# -*- coding: UTF-8 -*-


import abc


class IVerifiable(object, metaclass = abc.ABCMeta):
    @abc.abstractmethod
    def verify(self):
        raise NotImplementedError
