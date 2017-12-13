# -*- coding: UTF-8 -*-


import abc

from Tools.Logger import logger


class IPlugin(object, metaclass = abc.ABCMeta):
    name = None

    @abc.abstractmethod
    def verify(self, *args, **kwargs):
        raise NotImplementedError

    @abc.abstractmethod
    def on_plugin_load(self, *args, **kwargs):
        raise NotImplementedError

    @abc.abstractmethod
    def on_plugin_unload(self, *args, **kwargs):
        raise NotImplementedError


class ISupportPlugin(object, metaclass = abc.ABCMeta):
    enabled_plugins = None

    def _load_plugin(self, *args, **kwargs):
        for plugin in self.enabled_plugins:
            plugin_instance = plugin()

            logger.debug("Loading plugin {plugin_name}...".format(plugin_name = plugin_instance.name))
            if plugin_instance.verify(*args, **kwargs):
                logger.debug("Passed the plugin verification.")

                logger.debug("Loading the plugin...")
                plugin_instance.on_plugin_load(*args, **kwargs)

                logger.debug("Unloading the plugin...")
                plugin_instance.on_plugin_unload(*args, **kwargs)
            else:
                logger.error("Failed the plugin verification.")

    @abc.abstractmethod
    def load_plugin(self, *args, **kwargs):
        raise NotImplementedError
