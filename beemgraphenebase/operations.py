# -*- coding: utf-8 -*-
from collections import OrderedDict
from .types import (
    String, Set
)
from .objects import GrapheneObject, isArgsThisClass


class Demooepration(GrapheneObject):
    def __init__(self, *args, **kwargs):
        if isArgsThisClass(self, args):
                self.data = args[0].data
        else:
            if len(args) == 1 and len(kwargs) == 0:
                kwargs = args[0]
            super(Demooepration, self).__init__(OrderedDict([
                ('string', String(kwargs["string"], "account")),
                ('extensions', Set([])),
            ]))
