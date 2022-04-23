import { clearProps, getParametersValue } from "pvutils";

import { compareSchema, Constructed, Integer, OctetString, Primitive, Repeated, Sequence } from "./asn1";
import GeneralName from "./GeneralName";
//* *************************************************************************************
/**
 * Class from RFC5280
 */
export default class AuthorityKeyIdentifier
{
	//* *********************************************************************************
	/**
	 * Constructor for AuthorityKeyIdentifier class
	 * @param {Object} [parameters={}]
	 * @param {Object} [parameters.schema] asn1js parsed value to initialize the class from
	 */
	constructor(parameters = {})
	{
		// region Internal properties of the object
		if("keyIdentifier" in parameters)
			/**
			 * @type {OctetString}
			 * @desc keyIdentifier
			 */
			{this.keyIdentifier = getParametersValue(parameters, "keyIdentifier", AuthorityKeyIdentifier.defaultValues("keyIdentifier"));}

		if("authorityCertIssuer" in parameters)
			/**
			 * @type {Array.<GeneralName>}
			 * @desc authorityCertIssuer
			 */
			{this.authorityCertIssuer = getParametersValue(parameters, "authorityCertIssuer", AuthorityKeyIdentifier.defaultValues("authorityCertIssuer"));}

		if("authorityCertSerialNumber" in parameters)
			/**
			 * @type {Integer}
			 * @desc authorityCertIssuer
			 */
			{this.authorityCertSerialNumber = getParametersValue(parameters, "authorityCertSerialNumber", AuthorityKeyIdentifier.defaultValues("authorityCertSerialNumber"));}
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
			case "keyIdentifier":
				return new OctetString();
			case "authorityCertIssuer":
				return [];
			case "authorityCertSerialNumber":
				return new Integer();
			default:
				throw new Error(`Invalid member name for AuthorityKeyIdentifier class: ${memberName}`);
		}
	}

	//* *********************************************************************************
	/**
	 * Return value of pre-defined ASN.1 schema for current class
	 *
	 * ASN.1 schema:
	 * ```asn1
	 * AuthorityKeyIdentifier OID ::= 2.5.29.35
	 *
	 * AuthorityKeyIdentifier ::= SEQUENCE {
	 *    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
	 *    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
	 *    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
	 *
	 * KeyIdentifier ::= OCTET STRING
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
		 * @property {string} [keyIdentifier]
		 * @property {string} [authorityCertIssuer]
		 * @property {string} [authorityCertSerialNumber]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Primitive({
					name: (names.keyIdentifier || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					}
				}),
				new Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [
						new Repeated({
							name: (names.authorityCertIssuer || ""),
							value: GeneralName.schema()
						})
					]
				}),
				new Primitive({
					name: (names.authorityCertSerialNumber || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					}
				})
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
			"keyIdentifier",
			"authorityCertIssuer",
			"authorityCertSerialNumber"
		]);
		// endregion
		
		// region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			AuthorityKeyIdentifier.schema({
				names: {
					keyIdentifier: "keyIdentifier",
					authorityCertIssuer: "authorityCertIssuer",
					authorityCertSerialNumber: "authorityCertSerialNumber"
				}
			})
		);

		if(asn1.verified === false)
			{throw new Error("Object's schema was not verified against input data for AuthorityKeyIdentifier");}
		// endregion

		// region Get internal properties from parsed schema
		if("keyIdentifier" in asn1.result)
			{this.keyIdentifier = new OctetString({ valueHex: asn1.result.keyIdentifier.valueBlock.valueHex });}

		if("authorityCertIssuer" in asn1.result)
			{this.authorityCertIssuer = Array.from(asn1.result.authorityCertIssuer, element => new GeneralName({ schema: element }));}

		if("authorityCertSerialNumber" in asn1.result)
			{this.authorityCertSerialNumber = new Integer({ valueHex: asn1.result.authorityCertSerialNumber.valueBlock.valueHex });}
		// endregion
	}

	//* *********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		// region Create array for output sequence
		const outputArray = [];
		
		if("keyIdentifier" in this)
		{
			outputArray.push(new Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				valueHex: this.keyIdentifier.valueBlock.valueHex
			}));
		}
		
		if("authorityCertIssuer" in this)
		{
			outputArray.push(new Constructed({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				value: Array.from(this.authorityCertIssuer, element => element.toSchema())
			}));
		}
		
		if("authorityCertSerialNumber" in this)
		{
			outputArray.push(new Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 2 // [2]
				},
				valueHex: this.authorityCertSerialNumber.valueBlock.valueHex
			}));
		}
		// endregion
		
		// region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: outputArray
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
		const object = {};

		if("keyIdentifier" in this)
			{object.keyIdentifier = this.keyIdentifier.toJSON();}

		if("authorityCertIssuer" in this)
			{object.authorityCertIssuer = Array.from(this.authorityCertIssuer, element => element.toJSON());}

		if("authorityCertSerialNumber" in this)
			{object.authorityCertSerialNumber = this.authorityCertSerialNumber.toJSON();}

		return object;
	}
	//* *********************************************************************************
}
//* *************************************************************************************
