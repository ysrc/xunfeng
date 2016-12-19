#    U32.py implements 32-bit unsigned int class for Python
#    Version 1.0
#    Copyright (C) 2001-2002  Dmitry Rozmanov
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#    e-mail: dima@xenon.spb.ru
#
#====================================================================

C = 0x1000000000L

#--------------------------------------------------------------------
def norm(n):
    return n & 0xFFFFFFFFL

#====================================================================
class U32:
    v = 0L

    #--------------------------------------------------------------------
    def __init__(self, value = 0):
        self.v = C + norm(abs(long(value)))

    #--------------------------------------------------------------------
    def set(self, value = 0):
        self.v = C + norm(abs(long(value)))

    #--------------------------------------------------------------------
    def __repr__(self):
        return hex(norm(self.v))

    #--------------------------------------------------------------------
    def __long__(self): return long(norm(self.v))

    #--------------------------------------------------------------------
    def __int__(self): return int(norm(self.v))

    #--------------------------------------------------------------------
    def __chr__(self): return chr(norm(self.v))

    #--------------------------------------------------------------------
    def __add__(self, b):
        r = U32()
        r.v = C + norm(self.v + b.v)
        return r

    #--------------------------------------------------------------------
    def __sub__(self, b):
        r = U32()
        if self.v < b.v:
            r.v = C + norm(0x100000000L - (b.v - self.v))
        else: r.v = C + norm(self.v - b.v)
        return r

    #--------------------------------------------------------------------
    def __mul__(self, b):
        r = U32()
        r.v = C + norm(self.v * b.v)
        return r

    #--------------------------------------------------------------------
    def __div__(self, b):
        r = U32()
        r.v = C + (norm(self.v) / norm(b.v))
        return r

    #--------------------------------------------------------------------
    def __mod__(self, b):
        r = U32()
        r.v = C + (norm(self.v) % norm(b.v))
        return r

    #--------------------------------------------------------------------
    def __neg__(self): return U32(self.v)

    #--------------------------------------------------------------------
    def __pos__(self): return U32(self.v)

    #--------------------------------------------------------------------
    def __abs__(self): return U32(self.v)

    #--------------------------------------------------------------------
    def __invert__(self):
        r = U32()
        r.v = C + norm(~self.v)
        return r

    #--------------------------------------------------------------------
    def __lshift__(self, b):
        r = U32()
        r.v = C + norm(self.v << b)
        return r

    #--------------------------------------------------------------------
    def __rshift__(self, b):
        r = U32()
        r.v = C + (norm(self.v) >> b)
        return r

    #--------------------------------------------------------------------
    def __and__(self, b):
        r = U32()
        r.v = C + norm(self.v & b.v)
        return r

    #--------------------------------------------------------------------
    def __or__(self, b):
        r = U32()
        r.v = C + norm(self.v | b.v)
        return r

    #--------------------------------------------------------------------
    def __xor__(self, b):
        r = U32()
        r.v = C + norm(self.v ^ b.v)
        return r

    #--------------------------------------------------------------------
    def __not__(self):
        return U32(not norm(self.v))

    #--------------------------------------------------------------------
    def truth(self):
        return norm(self.v)

    #--------------------------------------------------------------------
    def __cmp__(self, b):
        if norm(self.v) > norm(b.v): return 1
        elif norm(self.v) < norm(b.v): return -1
        else: return 0

    #--------------------------------------------------------------------
    def __nonzero__(self):
        return norm(self.v)
        
