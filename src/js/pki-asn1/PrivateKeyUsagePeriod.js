import { clearProps, getParametersValue } from "pvutils";

import { compareSchema, GeneralizedTime, Primitive, Sequence } from "./asn1";
//* *************************************************************************************
/**
 * Class from RFC5280
 */
export default class PrivateKeyUsagePeriod
{
	//* *********************************************************************************
	/**
	 * Constructor for PrivateKeyUsagePeriod class
	 * @param {Object} [parameters={}]
	 * @param {Object} [parameters.schema] asn1js parsed value to initialize the class from
	 */
	constructor(parameters = {})
	{
		// region Internal properties of the object
		if("notBefore" in parameters)
			/**
			 * @type {Date}
			 * @desc notBefore
			 */
			{this.notBefore = getParametersValue(parameters, "notBefore", PrivateKeyUsagePeriod.defaultValues("notBefore"));}

		if("notAfter" in parameters)
			/**
			 * @type {Date}
			 * @desc notAfter
			 */
			{this.notAfter = getParametersValue(parameters, "notAfter", PrivateKeyUsagePeriod.defaultValues("notAfter"));}
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
			case "notBefore":
				return new Date();
			case "notAfter":
				return new Date();
			default:
				throw new Error(`Invalid member name for PrivateKeyUsagePeriod class: ${memberName}`);
		}
	}

	//* *********************************************************************************
	/**
	 * Return value of pre-defined ASN.1 schema for current class
	 *
	 * ASN.1 schema:
	 * ```asn1
	 * PrivateKeyUsagePeriod OID ::= 2.5.29.16
	 *
	 * PrivateKeyUsagePeriod ::= SEQUENCE {
	 *    notBefore       [0]     GeneralizedTime OPTIONAL,
	 *    notAfter        [1]     GeneralizedTime OPTIONAL }
	 * -- either notBefore or notAfter MUST be present
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
		 * @property {string} [notBefore]
		 * @property {string} [notAfter]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new Primitive({
					name: (names.notBefore || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					}
				}),
				new Primitive({
					name: (names.notAfter || ""),
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
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
			"notBefore",
			"notAfter"
		]);
		// endregion
		
		// region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			PrivateKeyUsagePeriod.schema({
				names: {
					notBefore: "notBefore",
					notAfter: "notAfter"
				}
			})
		);

		if(asn1.verified === false)
			{throw new Error("Object's schema was not verified against input data for PrivateKeyUsagePeriod");}
		// endregion

		// region Get internal properties from parsed schema
		if("notBefore" in asn1.result)
		{
			const localNotBefore = new GeneralizedTime();

			localNotBefore.fromBuffer(asn1.result.notBefore.valueBlock.valueHex);
			this.notBefore = localNotBefore.toDate();
		}

		if("notAfter" in asn1.result)
		{
			const localNotAfter = new GeneralizedTime({ valueHex: asn1.result.notAfter.valueBlock.valueHex });

			localNotAfter.fromBuffer(asn1.result.notAfter.valueBlock.valueHex);
			this.notAfter = localNotAfter.toDate();
		}
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
		
		if("notBefore" in this)
		{
			outputArray.push(new Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				valueHex: (new GeneralizedTime({ valueDate: this.notBefore })).valueBlock.valueHex
			}));
		}
		
		if("notAfter" in this)
		{
			outputArray.push(new Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				valueHex: (new GeneralizedTime({ valueDate: this.notAfter })).valueBlock.valueHex
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

		if("notBefore" in this)
			{object.notBefore = this.notBefore;}

		if("notAfter" in this)
			{object.notAfter = this.notAfter;}

		return object;
	}
	//* *********************************************************************************
}
//* *************************************************************************************
