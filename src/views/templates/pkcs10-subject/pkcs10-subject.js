import './pkcs10-subject.scss'
import { arrayBufferToString, fromBase64, stringToArrayBuffer, toBase64 } from "pvutils";
import { 
	BmpString, 
	CharacterString, 
	fromBER,
	GeneralString, 
	GraphicString, 
	IA5String,
	NumericString,
	OctetString,
	PrintableString,
	TeletexString,
	UniversalString,
	Utf8String,
	VideotexString,
	VisibleString
} from "src/js/pki-asn1/asn1";
import Attribute from "src/js/pki-asn1/Attribute";
import AttributeTypeAndValue from "src/js/pki-asn1/AttributeTypeAndValue";
import CertificationRequest from "src/js/pki-asn1/CertificationRequest";
import { getAlgorithmParameters, getCrypto } from "src/js/pki-asn1/common";
import { formatPEM } from "src/js/pki-asn1/examples_common";
import Extension from "src/js/pki-asn1/Extension";
import Extensions from "src/js/pki-asn1/Extensions";
import GeneralName from "src/js/pki-asn1/GeneralName";
import GeneralNames from "src/js/pki-asn1/GeneralNames";
import RSAPublicKey from "src/js/pki-asn1/RSAPublicKey";

// <nodewebcryptoossl>
//* ********************************************************************************
let pkcs10Buffer = new ArrayBuffer(0);

let hashAlg = "SHA-1";

let signAlg = "RSASSA-PKCS1-V1_5";

let subjectCN = "Simple test (простой тест)";

let dNSName = "www.domain.com";

//* ********************************************************************************
// region Create PKCS#10
//* ********************************************************************************

window.createPKCS10Internal = () =>
{
	// region Initial variables
	let sequence = Promise.resolve();
	
	const pkcs10 = new CertificationRequest();
	
	let publicKey;

	let privateKey;
	// endregion
	
	// region Get a "crypto" extension
	const crypto = getCrypto();

	if(typeof crypto === "undefined")

		{return Promise.reject(new Error("No WebCrypto extension found"));}
	// endregion
	
	// region Put a static values
	pkcs10.version = 0;
	// pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
	// 	type: "2.5.4.6",
	// 	value: new asn1js.PrintableString({ value: "RU" })
	// }));
	pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.3",
		value: new Utf8String({ value: subjectCN })
	}));
	
	const altNames = new GeneralNames({
		names: [
			// new GeneralName({
			// 	type: 1, // rfc822Name
			// 	value: "email@address.com"
			// }),
			new GeneralName({
				type: 2, // dNSName
				value: dNSName
			}),
			// new GeneralName({
			// 	type: 2, // dNSName
			// 	value: "www.anotherdomain.com"
			// }),
			// new GeneralName({
			// 	type: 7, // iPAddress
			// 	value: new asn1js.OctetString({ valueHex: (new Uint8Array([0xC0, 0xA8, 0x00, 0x01])).buffer })
			// }),
		]
	});
	
	pkcs10.attributes = [];
	// endregion
	
	// region Create a new key pair
	sequence = sequence.then(() =>
	{
		// region Get default algorithm parameters for key generation
		const algorithm = getAlgorithmParameters(signAlg, "generatekey");

		if("hash" in algorithm.algorithm)
			{algorithm.algorithm.hash.name = hashAlg;}
		// endregion
		
		return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
	});
	// endregion
	
	// region Store new key in an interim variables
	sequence = sequence.then(keyPair =>
	{
		publicKey = keyPair.publicKey;
		privateKey = keyPair.privateKey;
	},
	error => Promise.reject(new Error(`Error during key generation: ${error}`))
	);
	// endregion
	
	// region Exporting public key into "subjectPublicKeyInfo" value of PKCS#10
	sequence = sequence.then(() => pkcs10.subjectPublicKeyInfo.importKey(publicKey));
	// endregion
	
	// region SubjectKeyIdentifier
	sequence = sequence.then(() => crypto.digest({ name: "SHA-1" }, pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex))
		.then(result =>
		{
			pkcs10.attributes.push(new Attribute({
				type: "1.2.840.113549.1.9.14", // pkcs-9-at-extensionRequest
				values: [(new Extensions({
					extensions: [
						new Extension({
							extnID: "2.5.29.14",
							critical: false,
							extnValue: (new OctetString({ valueHex: result })).toBER(false)
						}),
						new Extension({
							extnID: "2.5.29.17",
							critical: false,
							extnValue: altNames.toSchema().toBER(false)
						}),
						new Extension({
							extnID: "1.2.840.113549.1.9.7",
							critical: false,
							extnValue: (new PrintableString({ value: "passwordChallenge" })).toBER(false)
						})
					]
				})).toSchema()]
			}));
		}
		);
	// endregion
	
	// region Signing final PKCS#10 request
	sequence = sequence.then(() => pkcs10.sign(privateKey, hashAlg), error => Promise.reject(new Error(`Error during exporting public key: ${error}`)));
	// endregion
	
	return sequence.then(() =>
	{
		pkcs10Buffer = pkcs10.toSchema().toBER(false);
		
	}, error => Promise.reject(new Error(`Error signing PKCS#10: ${error}`)));
}

//* ********************************************************************************
window.createPKCS10 = () =>
Promise.resolve().then(() => window.createPKCS10Internal()).then(() =>
	{
		let resultString = "-----BEGIN CERTIFICATE REQUEST-----\r\n";

		resultString = `${resultString}${formatPEM(toBase64(arrayBufferToString(pkcs10Buffer)))}`;
		resultString = `${resultString}\r\n-----END CERTIFICATE REQUEST-----\r\n`;
		
		document.getElementById("pem-text-block").value = resultString;

		window.parsePKCS10();
	})

//* ********************************************************************************
// endregion
//* ********************************************************************************
// region Parse existing PKCS#10
//* ********************************************************************************
window.parsePKCS10 = () =>
{
	// region Initial activities
	// noinspection InnerHTMLJS
	document.getElementById("pkcs10-subject").innerHTML = "";
	// noinspection InnerHTMLJS
	document.getElementById("pkcs10-exten").innerHTML = "";
	
	document.getElementById("pkcs10-data-block").style.display = "none";
	document.getElementById("pkcs10-attributes").style.display = "none";
	// endregion
	
	// region Decode existing PKCS#10
	const stringPEM = document.getElementById("pem-text-block").value.replace(/(-----(BEGIN|END) CERTIFICATE REQUEST-----|\n)/g, "");

	const asn1 = fromBER(stringToArrayBuffer(fromBase64((stringPEM))));

	const pkcs10 = new CertificationRequest({ schema: asn1.result });
	// endregion
	
	// region Parse and display information about "subject"
	const typemap = {
		"2.5.4.6": "C",
		"2.5.4.11": "OU",
		"2.5.4.10": "O",
		"2.5.4.3": "CN",
		"2.5.4.7": "L",
		"2.5.4.8": "ST",
		"2.5.4.12": "T",
		"2.5.4.42": "GN",
		"2.5.4.43": "I",
		"2.5.4.4": "SN",
		"1.2.840.113549.1.9.1": "E-mail"
	};

	for(let i = 0; i < pkcs10.subject.typesAndValues.length; i += 1)
	{
		let typeval = typemap[pkcs10.subject.typesAndValues[i].type];

		if(typeof typeval === "undefined")
			{typeval = pkcs10.subject.typesAndValues[i].type;}
		
		const subjval = pkcs10.subject.typesAndValues[i].value.valueBlock.value;
		const ulrow = `<li><p><span>${typeval}</span> ${subjval}</p></li>`;
		
		// noinspection InnerHTMLJS
		document.getElementById("pkcs10-subject").innerHTML = document.getElementById("pkcs10-subject").innerHTML + ulrow;
		if(typeval === "CN")
		{
			// noinspection InnerHTMLJS
			document.getElementById("pkcs10-subject-cn").innerHTML = subjval;
		}
	}
	// endregion
	
	// region Put information about public key size
	let publicKeySize = "< unknown >";
	
	if(pkcs10.subjectPublicKeyInfo.algorithm.algorithmId.indexOf("1.2.840.113549") !== (-1))
	{
		const asn1PublicKey = fromBER(pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex);
		const rsaPublicKeySimple = new RSAPublicKey({ schema: asn1PublicKey.result });
		const modulusView = new Uint8Array(rsaPublicKeySimple.modulus.valueBlock.valueHex);

		let modulusBitLength = 0;
		
		if(modulusView[0] === 0x00)
			{modulusBitLength = (rsaPublicKeySimple.modulus.valueBlock.valueHex.byteLength - 1) * 8;}
		else
			{modulusBitLength = rsaPublicKeySimple.modulus.valueBlock.valueHex.byteLength * 8;}
		
		publicKeySize = modulusBitLength.toString();
	}
	
	// noinspection InnerHTMLJS
	document.getElementById("keysize").innerHTML = publicKeySize;
	// endregion
	
	// region Put information about signature algorithm
	const algomap = {
		"1.2.840.113549.1.1.2": "MD2 with RSA",
		"1.2.840.113549.1.1.4": "MD5 with RSA",
		"1.2.840.10040.4.3": "SHA1 with DSA",
		"1.2.840.10045.4.1": "SHA1 with ECDSA",
		"1.2.840.10045.4.3.2": "SHA256 with ECDSA",
		"1.2.840.10045.4.3.3": "SHA384 with ECDSA",
		"1.2.840.10045.4.3.4": "SHA512 with ECDSA",
		"1.2.840.113549.1.1.10": "RSA-PSS",
		"1.2.840.113549.1.1.5": "SHA1 with RSA",
		"1.2.840.113549.1.1.14": "SHA224 with RSA",
		"1.2.840.113549.1.1.11": "SHA256 with RSA",
		"1.2.840.113549.1.1.12": "SHA384 with RSA",
		"1.2.840.113549.1.1.13": "SHA512 with RSA"
	};

	let signatureAlgorithm = algomap[pkcs10.signatureAlgorithm.algorithmId];

	if(typeof signatureAlgorithm === "undefined")
		{signatureAlgorithm = pkcs10.signatureAlgorithm.algorithmId;}
	else
		{signatureAlgorithm = `${signatureAlgorithm} (${pkcs10.signatureAlgorithm.algorithmId})`;}
	
	// noinspection InnerHTMLJS
	document.getElementById("sig-algo").innerHTML = signatureAlgorithm;
	// endregion
	
	// region Put information about PKCS#10 attributes
	if("attributes" in pkcs10)
	{

		console.log('pkcs10', pkcs10);
		console.log('attributes OctetString', pkcs10.attributes[0].values[0].valueBlock.value[1].valueBlock.value[1].valueBlock.value[0].valueBlock.value[0].valueBlock.valueHex);
		const jsonTest = 					pkcs10.attributes[0].values[0].valueBlock.value[1].valueBlock.value[1].valueBlock.value[0].valueBlock.value[0].valueBlock.valueHex
		const enc = new TextDecoder("utf-8");

		console.log('attributes jsonTest', enc.decode(jsonTest));

		for(let i = 0; i < pkcs10.attributes.length; i += 1)
		{
			const typeval = pkcs10.attributes[i].type;

			let subjval = "";
			
			for(let j = 0; j < pkcs10.attributes[i].values.length; j += 1)
			{
				// noinspection OverlyComplexBooleanExpressionJS
				if((pkcs10.attributes[i].values[j] instanceof Utf8String) ||
					(pkcs10.attributes[i].values[j] instanceof BmpString) ||
					(pkcs10.attributes[i].values[j] instanceof UniversalString) ||
					(pkcs10.attributes[i].values[j] instanceof NumericString) ||
					(pkcs10.attributes[i].values[j] instanceof PrintableString) ||
					(pkcs10.attributes[i].values[j] instanceof TeletexString) ||
					(pkcs10.attributes[i].values[j] instanceof VideotexString) ||
					(pkcs10.attributes[i].values[j] instanceof IA5String) ||
					(pkcs10.attributes[i].values[j] instanceof GraphicString) ||
					(pkcs10.attributes[i].values[j] instanceof VisibleString) ||
					(pkcs10.attributes[i].values[j] instanceof GeneralString) ||
					(pkcs10.attributes[i].values[j] instanceof CharacterString))
				{
					subjval = subjval + ((subjval.length === 0) ? "" : ";") + pkcs10.attributes[i].values[j].valueBlock.value;
				}
				else
				{
					subjval = subjval + ((subjval.length === 0) ? "" : ";") + enc.decode(pkcs10.attributes[i].values[0].valueBlock.value[1].valueBlock.value[1].valueBlock.value[0].valueHex);
					console.log('attributes OctetString',                     enc.decode(pkcs10.attributes[i].values[0].valueBlock.value[0].valueBlock.value[0].valueBlock.value[0].valueHex));
					console.log('attributes OctetString',                                pkcs10.attributes[i].values[0].valueBlock.value[0].valueBlock.value[0].valueBlock);
					console.log('attributes OctetString',                                pkcs10.attributes[i].values[0].valueBlock.value[2].valueBlock.value[1].valueBlock.value[0].valueBlock.value);

				}



			}
			
			const ulrow = `<li><p><span>${typeval}</span> ${subjval}</p></li>`;
			// noinspection InnerHTMLJS

			document.getElementById("pkcs10-exten").innerHTML = document.getElementById("pkcs10-exten").innerHTML + ulrow;
		}




		document.getElementById("pkcs10-attributes").style.display = "block";
		
	}
	// endregion
	
	document.getElementById("pkcs10-data-block").style.display = "block";
}

//* ********************************************************************************
// endregion
//* ********************************************************************************
// region Verify existing PKCS#10
//* ********************************************************************************
window.verifyPKCS10Internal = () =>
{
	// region Decode existing PKCS#10
	const asn1 = fromBER(pkcs10Buffer);
	const pkcs10 = new CertificationRequest({ schema: asn1.result });
	// endregion
	
	// region Verify PKCS#10
	return pkcs10.verify();
	// endregion
}

//* ********************************************************************************
window.verifyPKCS10 = () =>
Promise.resolve().then(() =>
	{
		pkcs10Buffer = stringToArrayBuffer(fromBase64(document.getElementById("pem-text-block").value.replace(/(-----(BEGIN|END) CERTIFICATE REQUEST-----|\n)/g, "")));
	}).then(() => window.verifyPKCS10Internal()).then(result =>
	{
		alert(`Verification passed: ${result}`);
	}, error =>
	{
		alert(`Error during verification: ${error}`);
	})

//* ********************************************************************************
// endregion
//* ********************************************************************************
window.handleHashAlgOnChange = () =>
{
	const hashOption = document.getElementById("hashAlg").value;

	switch(hashOption)
	{
		case "alg_SHA1":
			hashAlg = "sha-1";
			break;
		case "alg_SHA256":
			hashAlg = "sha-256";
			break;
		case "alg_SHA384":
			hashAlg = "sha-384";
			break;
		case "alg_SHA512":
			hashAlg = "sha-512";
			break;
		default:
	}
}

//* ********************************************************************************
window.handleSignAlgOnChange = () =>
{
	const signOption = document.getElementById("signAlg").value;

	switch(signOption)
	{
		case "alg_RSA15":
			signAlg = "RSASSA-PKCS1-V1_5";
			break;
		case "alg_RSA2":
			signAlg = "RSA-PSS";
			break;
		case "alg_ECDSA":
			signAlg = "ECDSA";
			break;
		default:
	}
}

//* ********************************************************************************
window.handleSubjectCNOnChange = () =>
{
	subjectCN = document.getElementById("subjectCN").value;
}

//* ********************************************************************************
window.handleAltNamesDNSNameOnChange = () =>
{
	dNSName = document.getElementById("altNamesDNSName").value;
}
