import { clearProps, getParametersValue } from "pvutils";

import { Any, compareSchema, Constructed, ObjectIdentifier, Sequence } from "./asn1";
//* *************************************************************************************
/**
 * Class from RFC7292
 */
export default class SecretBag
{
	//* *********************************************************************************
	/**
	 * Constructor for SecretBag class
	 * @param {Object} [parameters={}]
	 * @param {Object} [parameters.schema] asn1js parsed value to initialize the class from
	 */
	constructor(parameters = {})
	{
		// region Internal properties of the object
		/**
		 * @type {string}
		 * @desc secretTypeId
		 */
		this.secretTypeId = getParametersValue(parameters, "secretTypeId", SecretBag.defaultValues("secretTypeId"));
		/**
		 * @type {*}
		 * @desc secretValue
		 */
		this.secretValue = getParametersValue(parameters, "secretValue", SecretBag.defaultValues("secretValue"));
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
			case "secretTypeId":
				return "";
			case "secretValue":
				return (new Any());
			default:
				throw new Error(`Invalid member name for SecretBag class: ${memberName}`);
		}
	}

	//* *********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "secretTypeId":
				return (memberValue === "");
			case "secretValue":
				return (memberValue instanceof Any);
			default:
				throw new Error(`Invalid member name for SecretBag class: ${memberName}`);
		}
	}

	//* *********************************************************************************
	/**
	 * Return value of pre-defined ASN.1 schema for current class
	 *
	 * ASN.1 schema:
	 * ```asn1
	 * SecretBag ::= SEQUENCE {
	 *    secretTypeId BAG-TYPE.&id ({SecretTypes}),
	 *    secretValue  [0] EXPLICIT BAG-TYPE.&Type ({SecretTypes}{@secretTypeId})
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
		 * @property {string} [id]
		 * @property {string} [value]
		 */
		const names = getParametersValue(parameters, "names", {});
		
		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.id || "id") }),
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new Any({ name: (names.value || "value") })] // EXPLICIT ANY value
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
			"secretTypeId",
			"secretValue"
		]);
		// endregion
		
		// region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			SecretBag.schema({
				names: {
					id: "secretTypeId",
					value: "secretValue"
				}
			})
		);
		
		if(asn1.verified === false)
			{throw new Error("Object's schema was not verified against input data for SecretBag");}
		// endregion
		
		// region Get internal properties from parsed schema
		this.secretTypeId = asn1.result.secretTypeId.valueBlock.toString();
		this.secretValue = asn1.result.secretValue;
		// endregion
	}

	//* *********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		// region Construct and return new ASN.1 schema for this object
		return (new Sequence({
			value: [
				new ObjectIdentifier({ value: this.secretTypeId }),
				new Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [this.secretValue.toSchema()]
				})
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
		return {
			secretTypeId: this.secretTypeId,
			secretValue: this.secretValue.toJSON()
		};
	}
	//* *********************************************************************************
}
//* *************************************************************************************
