
from pyasn1.type import tag, univ, namedtype, namedval, constraint
from pyasn1.codec.der import encoder, decoder

__all__ = [ 'generateNegotiateSecurityBlob', 'generateAuthSecurityBlob', 'decodeChallengeSecurityBlob', 'decodeAuthResponseSecurityBlob' ]


class UnsupportedSecurityProvider(Exception): pass
class BadSecurityBlobError(Exception): pass


def generateNegotiateSecurityBlob(ntlm_data):
    mech_token = univ.OctetString(ntlm_data).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
    mech_types = MechTypeList().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    mech_types.setComponentByPosition(0, univ.ObjectIdentifier('1.3.6.1.4.1.311.2.2.10'))

    n = NegTokenInit().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    n.setComponentByName('mechTypes', mech_types)
    n.setComponentByName('mechToken', mech_token)

    nt = NegotiationToken()
    nt.setComponentByName('negTokenInit', n)

    ct = ContextToken()
    ct.setComponentByName('thisMech', univ.ObjectIdentifier('1.3.6.1.5.5.2'))
    ct.setComponentByName('innerContextToken', nt)

    return encoder.encode(ct)


def generateAuthSecurityBlob(ntlm_data):
    response_token = univ.OctetString(ntlm_data).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))

    n = NegTokenTarg().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
    n.setComponentByName('responseToken', response_token)

    nt = NegotiationToken()
    nt.setComponentByName('negTokenTarg', n)

    return encoder.encode(nt)


def decodeChallengeSecurityBlob(data):
    try:
        d, _ = decoder.decode(data, asn1Spec = NegotiationToken())
        nt = d.getComponentByName('negTokenTarg')

        token = nt.getComponentByName('responseToken')
        if not token:
            raise BadSecurityBlobError('NTLMSSP_CHALLENGE security blob does not contain responseToken field')

        provider_oid = nt.getComponentByName('supportedMech')
        if provider_oid and str(provider_oid) != '1.3.6.1.4.1.311.2.2.10':  # This OID is defined in [MS-NLMP]: 1.9
            raise UnsupportedSecurityProvider('Security provider "%s" is not supported by pysmb' % str(provider_oid))

        result = nt.getComponentByName('negResult')
        return int(result), str(token)
    except Exception, ex:
        raise BadSecurityBlobError(str(ex))


def decodeAuthResponseSecurityBlob(data):
    try:
        d, _ = decoder.decode(data, asn1Spec = NegotiationToken())
        nt = d.getComponentByName('negTokenTarg')

        result = nt.getComponentByName('negResult')
        return int(result)
    except Exception, ex:
        raise BadSecurityBlobError(str(ex))


#
# GSS-API ASN.1 (RFC2478 section 3.2.1)
#

RESULT_ACCEPT_COMPLETED = 0
RESULT_ACCEPT_INCOMPLETE = 1
RESULT_REJECT = 2

class NegResultEnumerated(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ( 'accept_completed', 0 ),
        ( 'accept_incomplete', 1 ),
        ( 'reject', 2 )
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + constraint.SingleValueConstraint(0, 1, 2)


class MechTypeList(univ.SequenceOf):
    componentType = univ.ObjectIdentifier()


class ContextFlags(univ.BitString):
    namedValues = namedval.NamedValues(
        ( 'delegFlag', 0 ),
        ( 'mutualFlag', 1 ),
        ( 'replayFlag', 2 ),
        ( 'sequenceFlag', 3 ),
        ( 'anonFlag', 4 ),
        ( 'confFlag', 5 ),
        ( 'integFlag', 6 )
    )


class NegTokenInit(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('mechTypes', MechTypeList().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('reqFlags', ContextFlags().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('mechToken', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.OptionalNamedType('mechListMIC', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)))
    )


class NegTokenTarg(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('negResult', NegResultEnumerated().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('supportedMech', univ.ObjectIdentifier().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('responseToken', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.OptionalNamedType('mechListMIC', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)))
    )


class NegotiationToken(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('negTokenInit', NegTokenInit().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('negTokenTarg', NegTokenTarg().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    )


class ContextToken(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('thisMech', univ.ObjectIdentifier()),
        namedtype.NamedType('innerContextToken', NegotiationToken())
    )
