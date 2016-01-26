# -*- coding: utf-8 -*-
#
# Copyright © 2016 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from collections import Mapping, OrderedDict, defaultdict
import copy
import re

import slip.dbus.service

from rolekit.errors import RolekitError, INVALID_VALUE

_Unset = object()
UNLIMITED = object()

__all__ = (
    'RoleSettingBase', 'RoleSetting', 'RoleSettingList', 'RoleSettingGroup',
    'RoleSettingsMixin')


############################################################################
#
# RoleSetting, RoleSettingList, RoleSettingGroup and friends
#
############################################################################

class RoleSettingBase(object):

    """Base class for scalar and compound settings descriptors"""

    # only set on factory classes
    _clsname = None

    # authoritative source of what may go into the constructor, with default
    # values for pretty-printing and optional custom print formats
    _constructor_args_defaults_pformats = (
        ('name', None, "{value!r}"),
        ('type', None, "{name}={value.__name__}"),
        ('real_type', None, "{name}={value.__name__}"),
        ('default', None, None),
        ('required', True, None),
        ('constraint', None, None),
        ('readonly', False, None),
        ('sensitive', False, None)
    )

    _constructor_adp_dict = {
        a: (d, p) for a, d, p in _constructor_args_defaults_pformats}

    __slots__ = set(_constructor_adp_dict.keys()) + ('default_needs_copy',)

    def __init__(
            self, name=None, type=None, real_type=None, default=None,
            required=True, constraint=None, readonly=False, sensitive=False):
        self.name = name
        self.required = required
        # self.type can contain a named type, self.real_type should be set to a
        # real Python type in the constructor in that case
        self.type = type
        self.real_type = type if real_type is None else real_type
        self.default_needs_copy = not issubclass(type, (
            int, float, str, bool, tuple))
        if constraint is not None and not callable(constraint):
            raise TypeError(
                "constraint on setting {} must be callable, not {!r}".format(
                    self.name, constraint))
        self.constraint = constraint
        self.readonly = readonly
        self.sensitive = sensitive
        if default is not None and isinstance(default, str):
            self.default = self.cast_value(default)
        else:
            self.default = default
        if self.default is not None and not isinstance(
                self.default, self.real_type):
            raise TypeError(
                "{}: default must be of type {} or a string that can be "
                "converted into it".format(__class__, self.real_type))

    def __repr__(self):
        settings = []
        for name, default, pformat in self._constructor_args_defaults_pformats:
            value = getattr(self, name)
            if value == default:
                continue
            if pformat is None or value == 'type' and isinstance(value, str):
                pformat = "{name}={value!r}"
            settings.append(pformat.format(name=name, value=value))

        return "{}({})".format(
                self._clsname or self.__class__.__name__, ", ".join(settings))

    def cast_value(self, str_value):
        """Cast a string value into the desired settings type"""
        value = self.real_type(str_value)
        self.validate(value)
        return value

    def validate(self, value):
        """Validate that a correctly-typed value fulfils constraints, and
        return it."""

        if self.constraint is None:
            return value

        if not self.constraint(value):
            raise ValueError(
                "{!r} doesn't fulfil constraint for settings {}".format(
                    value, self.name))

    def clone(self, **kwargs):
        for argname in self._constructor_adp_dict:
            kwargs.setdefault(argname, getattr(self, argname))
        return type(self)(**kwargs)

# Scalar settings

class RoleSettingMeta(type):

    """Metaclass for `RoleSetting` and its subclasses to make these classes
    register themselves for the types for which they are responsible."""

    types_to_cls = {}

    def __new__(cls, name, bases, namespace, **kw):
        new_cls = type.__new__(cls, name, bases, dict(namespace))

        if name != 'RoleSetting':
            types = namespace.get('types')
            if not types:
                raise TypeError("{} must set types".format(name))
            if isinstance(types, str):
                types = (types,)
            else:
                try:
                    iter(types)
                except TypeError:
                    types = (types,)
            registered_already = []
            for type_ in types:
                if type_ in cls.types_to_cls:
                    registered_already.append(str(type_))
            if registered_already:
                raise TypeError(
                    "RoleSetting subclass(es) for {} registered already".format(
                        ", ".join(repr(registered_already))))

            for type_ in types:
                cls.types_to_cls[type_] = new_cls

        return new_cls


class _Unset(object):
    pass


class RoleSetting(RoleSettingBase, metaclass=RoleSettingMeta):

    """Descriptor class for scalar role settings"""

    _clsname = 'RoleSetting'

    def __new__(cls, *p, **kw):
        """Factory for specific sub types."""
        if cls is not RoleSetting:
            return super(RoleSetting, cls).__new__(cls)

        try:
            type = kw['type']
        except KeyError:
            raise ValueError("type must be set on {}".format(cls))
        return RoleSettingMeta.types_to_cls[type](*p, **kw)

    def __get__(self, obj, objtype):
        if not obj:
            return self

        value = obj._rolebase_settings.get(self.name, _Unset)

        if value is not _Unset:
            return value

        if self.default:
            if self.default_needs_copy:
                return copy.copy(self.default)
            else:
                return self.default

        if self.required:
            raise ValueError("{} required".format(self.name))

    def __set__(self, obj, value):
        obj._rolebase_settings[self.name] = self.cast_value(value)


class _RoleSettingBaseTypes(RoleSetting):

    types = (int, float, str)


class RoleSettingIPPort(RoleSetting):

    """A RoleSetting describing IP ports or port ranges."""

    types = 'ipport'

    port_syntax_re = re.compile(
        r'(?P<port>\d+)(?:-(?P<endport>\d+))?/(?P<protocol>tcp|udp)')

    def __init__(self, *args, **kwargs):
        super(RoleSettingIPPort, self).__init__(real_type=str, *args, **kwargs)

    def cast_value(self, str_value):
        return super(RoleSettingIPPort, self).cast_value(str_value.strip())

    def validate(self, value):
        m = self.port_syntax_re.match(value)
        if not m:
            raise ValueError(
                    "Can't parse IP port number/range: {!r}".format(value))
        port = int(m.group('port'))
        endport = int(m.group('endport'))
        if not 0 <= port <= 65535:
            raise ValueError("Port number must be between 0 and 65535")
        if endport is not None:
            if not 0 <= endport <= 65535:
                raise ValueError("End port number must be between 0 and 65535")
            if port >= endport:
                raise ValueError("End port must be greater than start port")


# compound settings

class RoleSettingList(RoleSettingBase):

    """Descriptor holding a list of typed settings"""


class RoleSettingGroupMeta(type):

    def __new__(cls, name, bases, namespace, **kw):
        _settings = OrderedDict()
        for name, attr in namespace.items():
            if isinstance(attr, (RoleSetting, RoleSettingList)):
                _settings[name] = attr
                if attr.name is None:
                    attr.name = name
        namespace['_settings'] = _settings
        super(RoleSettingGroupMeta, cls).__new__(
                cls, name, bases, namespace)


class RoleSettingGroup(object):

    """Group of named settings"""

    def __init__(self, **kwargs):
        if kwargs:
            self._settings = OrderedDict(__class__._settings)
            self._settings.update(kwargs)
        self._values = {}

    # object attribute interface

    def __getattr__(self, name):
        try:
            return self._settings[name]
        except KeyError:
            raise AttributeError("'{}' object has no attribute '{}'".format(
                __class__.__name__, name))

    def __setattr__(self, name, value):
        if isinstance(value, RoleSetting):
            self._settings[name] = value
        else:
            pass

    def clone_from_dict(self, value_dict):
        if not isinstance(value_dict, (Mapping, OrderedDict, defaultdict)):
            raise RolekitError(
                INVALID_VALUE,
                "{}.clone(): value_dict must be mapping".format(__class__))
        for k, v in value_dict.items():
            child = self._settings[k]
            if isinstance(child, RoleSettingGroup):
                child = child.clone_from_dict(v)
            else:
                child = child.clone(default=v)
            value_dict[k] = child
        return type(self)(**value_dict)


# metaclass and mixin for classes using settings

class RoleSettingsMixinMeta(slip.dbus.service.InterfaceType):

    basecls = None

    def __new__(cls, name, bases, namespace, **kwargs):
        if cls.basecls is None and name == 'RoleSettingsMixin':
            constructing_basecls = True
        else:
            constructing_basecls = False

            # prohibit member names starting with '_rolesettings' in classes
            # derived from RoleSettingsMixin
            reserved_membernames = [
                    x for x in namespace if x.startswith('_rolesettings')]
            if reserved_membernames:
                raise TypeError("Use of reserved member name(s): {}".format(
                    ", ".join(sorted(reserved_membernames))))

        # find role setting specific members in parent class(es)
        bases_settings = {}
        for base in bases:
            for aname in dir(base):
                if aname in bases_settings or aname.startswith("__"):
                    continue

                parent_attr = getattr(base, aname, None)
                if parent_attr and isinstance(
                        parent_attr, (RoleSettingBase, RoleSettingGroup)):
                    bases_settings[aname] = parent_attr

        for aname, attr in namespace.items():
            if isinstance(attr, RoleSetting) and attr.aname is None:
                attr.name = aname
                continue

            parent_attr = bases_settings.get(aname, None)
            if parent_attr:
                # if there is a parent attribute, copy and override the default

                # treat RoleSetting/List and RoleSettingGroup differently
                if isinstance(parent_attr, RoleSettingBase):
                    namespace[aname] = parent_attr.clone(default=attr)
                elif isinstance(parent_attr, RoleSettingGroup):
                    namespace[aname] = parent_attr.clone_from_dict(attr)
                else:
                    raise AssertionError(
                        "{}: parent settings attribute must be "
                        "of type RoleSetting, RoleSettingList or "
                        "RoleSettingGroup, not {}".format(
                            __class__, type(parent_attr.__name__)))

        newcls = super(slip.dbus.service.InterfaceType, cls).__new__(
                cls, name, bases, namespace, **kwargs)

        if constructing_basecls:
            cls.basecls = newcls

        return super(slip.dbus.service.InterfaceType, cls).__new__(
                cls, name, bases, namespace, **kwargs)


class RoleSettingsMixin(object, metaclass=RoleSettingsMixinMeta):

    def __init__(self):
        self._rolesettings = {}

    def settings_to_dict(self):
        pass
