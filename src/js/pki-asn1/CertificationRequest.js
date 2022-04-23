import { bufferToHexCodes, clearProps, getParametersValue } from "pvutils";

import AlgorithmIdentifier from "./AlgorithmIdentifier";
import { Any, BitString, compareSchema, Constructed, fromBER, Integer, ObjectIdentifier, Repeated, Sequence } from "./asn1";
import Attribute from "./Attribute";
import { getEngine } from "./common";
import PublicKeyInfo from "./PublicKeyInfo";
import RelativeDistinguishedNames from "./RelativeDistinguishedNames";
//* *************************************************************************************
function CertificationRequestInfo(parameters = {})
{
	// CertificationRequestInfo ::= SEQUENCE {
	//    version       INTEGER { v1(0) } (v1,...),
	//    subject       Name,
	//    subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
	//    attributes    [0] Attributes{{ CRIAttributes }}
	// }
	
	/**
	 * @type {Object}
	 * @property {string} [blockName]
	 * @property {string} [CertificationRequestInfo]
	 * @property {string} [CertificationRequestInfoVersion]
	 * @property {string} [subject]
	 * @property {string} [CertificationRequestInfoAttributes]
	 * @property {string} [attributes]
	 */
	const names = getParametersValue(parameters, "names", {});
	
	return (new Sequence({
		name: (names.CertificationRequestInfo || "CertificationRequestInfo"),
		value: [
			new Integer({ name: (names.CertificationRequestInfoVersion || "CertificationRequestInfo.version") }),
			RelativeDistinguishedNames.schema(names.subject || {
				names: {
					blockName: "CertificationRequestInfo.subject"
				}
			}),
			PublicKeyInfo.schema({
				names: {
					blockName: "CertificationRequestInfo.subjectPublicKeyInfo"
				}
			}),
			new Constructed({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: [
					new Repeated({
						optional: true, // Because OpenSSL makes wrong "attributes" field
						name: (names.CertificationRequestInfoAttributes || "CertificationRequestInfo.attributes"),
						value: Attribute.schema(names.attributes || {})
					})
				]
			})
		]
	}));
}

//* *************************************************************************************
/**
 * Class from RFC2986
 */
export default class CertificationRequest
{
	//* *********************************************************************************
	/**
	 * Constructor for Attribute class
	 * @param {Object} [parameters={}]
	 * @param {Object} [parameters.schema] asn1js parsed value to initialize the class from
	 */
	constructor(parameters = {})
	{
		// region Internal properties of the object
		/**
		 * @type {ArrayBuffer}
		 * @desc tbs
		 */
		this.tbs = getParametersValue(parameters, "tbs", CertificationRequest.defaultValues("tbs"));
		/**
		 * @type {number}
		 * @desc version
		 */
		this.version = getParametersValue(parameters, "version", CertificationRequest.defaultValues("version"));
		/**
		 * @type {RelativeDistinguishedNames}
		 * @desc subject
		 */
		this.subject = getParametersValue(parameters, "subject", CertificationRequest.defaultValues("subject"));
		/**
		 * @type {PublicKeyInfo}
		 * @desc subjectPublicKeyInfo
		 */
		this.subjectPublicKeyInfo = getParametersValue(parameters, "subjectPublicKeyInfo", CertificationRequest.defaultValues("subjectPublicKeyInfo"));
		
		if("attributes" in parameters)
			/**
			 * @type {Array.<Attribute>}
			 * @desc attributes
			 */
			{this.attributes = getParametersValue(parameters, "attributes", CertificationRequest.defaultValues("attributes"));}
		
		/**
		 * @type {AlgorithmIdentifier}
		 * @desc signatureAlgorithm
		 */
		this.signatureAlgorithm = getParametersValue(parameters, "signatureAlgorithm", CertificationRequest.defaultValues("signatureAlgorithm"));
		/**
		 * @type {BitString}
		 * @desc signatureAlgorithm
		 */
		this.signatureValue = getParametersValue(parameters, "signatureValue", CertificationRequest.defaultValues("signatureValue"));
		// endregion
		
		// region If input argument array contains "schema" for this object
		if("schema" in parameters)
			{this.fromSchema(parameters.schema);}
		// endregion
	}

	//* *********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "tbs":
				return new ArrayBuffer(0);
			case "version":
				return 0;
			case "subject":
				return new RelativeDistinguishedNames();
			case "subjectPublicKeyInfo":
				return new PublicKeyInfo();
			case "attributes":
				return [];
			case "signatureAlgorithm":
				return new AlgorithmIdentifier();
			case "signatureValue":
				return new BitString();
			default:
				throw new Error(`Invalid member name for CertificationRequest class: ${memberName}`);
		}
	}

	//* *********************************************************************************
	/**
	 * Return value of pre-defined ASN.1 schema for current class
	 *
	 * ASN.1 schema:
	 * ```asn1
	 * CertificationRequest ::= SEQUENCE {
	 *    certificationRequestInfo CertificationRequestInfo,
	 *    signatureAlgorithm       AlgorithmIdentifier{{ SignatureAlgorithms }},
	 *    signature                BIT STRING
	 * }
	 * ```
	 *
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [certificationRequestInfo]
		 * @property {string} [signatureAlgorithm]
		 * @property {string} [signatureValue]
		 */
		const names = getParametersValue(parameters, "names", {});
		
		return (new Sequence({
			value: [
				CertificationRequestInfo(names.certificationRequestInfo || {}),
				new Sequence({
					name: (names.signatureAlgorithm || "signatureAlgorithm"),
					value: [
						new ObjectIdentifier(),
						new Any({ optional: true })
					]
				}),
				new BitString({ name: (names.signatureValue || "signatureValue") })
			]
		}));
	}

	//* *********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		// region Clear input data first
		clearProps(schema, [
			"CertificationRequestInfo",
			"CertificationRequestInfo.version",
			"CertificationRequestInfo.subject",
			"CertificationRequestInfo.subjectPublicKeyInfo",
			"CertificationRequestInfo.attributes",
			"signatureAlgorithm",
			"signatureValue"
		]);
		// endregion
		
		// region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			CertificationRequest.schema()
		);
		
		if(asn1.verified === false)
			{throw new Error("Object's schema was not verified against input data for CertificationRequest");}
		// endregion
		
		// region Get internal properties from parsed schema
		this.tbs = asn1.result.CertificationRequestInfo.valueBeforeDecode;
		
		this.version = asn1.result["CertificationRequestInfo.version"].valueBlock.valueDec;
		this.subject = new RelativeDistinguishedNames({ schema: asn1.result["CertificationRequestInfo.subject"] });
		this.subjectPublicKeyInfo = new PublicKeyInfo({ schema: asn1.result["CertificationRequestInfo.subjectPublicKeyInfo"] });
		if("CertificationRequestInfo.attributes" in asn1.result)
			{this.attributes = Array.from(asn1.result["CertificationRequestInfo.attributes"], element => new Attribute({ schema: element }));}
		
		this.signatureAlgorithm = new AlgorithmIdentifier({ schema: asn1.result.signatureAlgorithm });
		this.signatureValue = asn1.result.signatureValue;
		// endregion
	}

	//* *********************************************************************************
	/**
	 * Aux function making ASN1js Sequence from current TBS
	 * @returns {Sequence}
	 */
	encodeTBS()
	{
		// region Create array for output sequence
		const outputArray = [
			new Integer({ value: this.version }),
			this.subject.toSchema(),
			this.subjectPublicKeyInfo.toSchema()
		];
		
		if("attributes" in this)
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				value: Array.from(this.attributes, element => element.toSchema())
			}));
		}
		// endregion
		
		return (new Sequence({
			value: outputArray
		}));
	}

	//* *********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema(encodeFlag = false)
	{
		// region Decode stored TBS value
		let tbsSchema;
		
		if(encodeFlag === false)
		{
			if(this.tbs.byteLength === 0) // No stored TBS part
				{return CertificationRequest.schema();}
			
			tbsSchema = fromBER(this.tbs).result;
		}
		// endregion
		// region Create TBS schema via assembling from TBS parts
		else
			{tbsSchema = this.encodeTBS();}
		// endregion
		
		// region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				tbsSchema,
				this.signatureAlgorithm.toSchema(),
				this.signatureValue
			]
		}));
		// endregion
	}

	//* *********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const object = {
			tbs: bufferToHexCodes(this.tbs, 0, this.tbs.byteLength),
			version: this.version,
			subject: this.subject.toJSON(),
			subjectPublicKeyInfo: this.subjectPublicKeyInfo.toJSON(),
			signatureAlgorithm: this.signatureAlgorithm.toJSON(),
			signatureValue: this.signatureValue.toJSON()
		};
		
		if("attributes" in this)
			{object.attributes = Array.from(this.attributes, element => element.toJSON());}
		
		return object;
	}

	//* *********************************************************************************
	/**
	 * Makes signature for currect certification request
	 * @param {Object} privateKey WebCrypto private key
	 * @param {string} [hashAlgorithm=SHA-1] String representing current hashing algorithm
	 */
	sign(privateKey, hashAlgorithm = "SHA-1")
	{
		// region Initial checking
		// region Get a private key from function parameter
		if(typeof privateKey === "undefined")
			// eslint-disable-next-line prefer-promise-reject-errors
			{return Promise.reject("Need to provide a private key for signing");}
		// endregion
		// endregion
		
		// region Initial variables
		let sequence = Promise.resolve();

		let parameters;
		
		const engine = getEngine();
		// endregion
		
		// region Get a "default parameters" for current algorithm and set correct signature algorithm
		sequence = sequence.then(() => engine.subtle.getSignatureParameters(privateKey, hashAlgorithm));
		
		sequence = sequence.then(result =>
		{
			parameters = result.parameters;
			this.signatureAlgorithm = result.signatureAlgorithm;
		});
		// endregion
		
		// region Create TBS data for signing
		sequence = sequence.then(() =>
		{
			this.tbs = this.encodeTBS().toBER(false);
		});
		// endregion
		
		// region Signing TBS data on provided private key
		sequence = sequence.then(() => engine.subtle.signWithPrivateKey(this.tbs, privateKey, parameters));
		
		sequence = sequence.then(result =>
		{
			this.signatureValue = new BitString({ valueHex: result });
		});
		// endregion
		
		return sequence;
	}

	//* *********************************************************************************
	/**
	 * Verify existing certification request signature
	 * @returns {*}
	 */
	verify()
	{
		return getEngine().subtle.verifyWithPublicKey(this.tbs, this.signatureValue, this.subjectPublicKeyInfo, this.signatureAlgorithm);
	}

	//* *********************************************************************************
	/**
	 * Importing public key for current certificate request
	 */
	getPublicKey(parameters = null)
	{
		return getEngine().getPublicKey(this.subjectPublicKeyInfo, this.signatureAlgorithm, parameters);
	}
	//* *********************************************************************************
}
//* *************************************************************************************
