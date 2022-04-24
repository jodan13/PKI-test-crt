import './about.scss'

import forge from 'node-forge'

// generate a key pair
const keys = forge.pki.rsa.generateKeyPair(2048);

// create a certification request (CSR)
let csr = forge.pki.createCertificationRequest();

csr.publicKey = keys.publicKey;
csr.setSubject([{
    name: 'commonName',
    value: 'Привет',
    valueTagClass: forge.asn1.Type.UTF8,
}, {
    name: 'countryName',
    value: 'US'
}, {
    shortName: 'ST',
    value: 'Virginia'
}, {
    name: 'localityName',
    value: 'Blacksburg'
}, {
    name: 'organizationName',
    value: 'Test'
}, {
    shortName: 'OU',
    value: 'Test'
}]);
// set (optional) attributes
csr.setAttributes([{
    name: 'challengePassword',
    value: 'password'
}, {
    name: 'unstructuredName',
    value: 'My Company, Inc.'
}, {
    name: 'extensionRequest',
    extensions: [{
        name: 'subjectAltName',
        altNames: [{
            // 2 is DNS type
            type: 2,
            value: 'test.domain.com'
        }, {
            type: 2,
            value: 'other.domain.com',
        },
            {
                type: 0,
                value: [
                    {
                        tagClass: 0,
                        type: 6,
                        value: "1.3.6.1.4.1.311.25.1"
                    },
                    {
                        tagClass: 128,
                        type: 0,
                        value: [
                            {
                                tagClass: 0,
                                type: 12,
                                value: "e4134486122d452495c771503eabf73f"
                            }
                        ]
                    }
                ]
            }
        ]
    }]
}]);

// sign certification request
csr.sign(keys.privateKey);

// verify certification request
// const verified = csr.verify();

// console.log('verified', verified)

// convert certification request to PEM-format
const pem = forge.pki.certificationRequestToPem(csr);

// convert a Forge certification request from PEM-format
csr = forge.pki.certificationRequestFromPem(pem);

// get an attribute
// csr.getAttribute({name: 'subject'});

// get extensions array
csr.getAttribute({name: 'extensionRequest'});

const pre = document.getElementById('pre')
const textarea = document.getElementById('pem-text-block')

textarea.value = pem
pre.innerText = JSON.stringify([csr.subject, csr.getAttribute({name: 'extensionRequest'}).extensions], null, 2)

window.parsePKCS10 = () => {
    const parce = forge.pki.certificationRequestFromPem(textarea.value)

    pre.innerText = JSON.stringify([parce.subject, parce.getAttribute({name: 'extensionRequest'}).extensions], null, 2)
}
