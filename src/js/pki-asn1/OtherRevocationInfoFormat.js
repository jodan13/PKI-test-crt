import { clearProps, getParametersValue } from "pvutils";

import { Any, compareSchema, ObjectIdentifier, Sequence } from "./asn1";
//* *************************************************************************************
/**
 * Class from RFC5652
 */
export default class OtherRevocationInfoFormat
{
	//* *********************************************************************************
	/**
	 * Constructor for OtherRevocationInfoFormat class
	 * @param {Object} [parameters={}]
	 * @param {Object} [parameters.schema] asn1js parsed value to initialize the class from
	 */
	constructor(parameters = {})
	{
		// region Internal properties of the object
		/**
		 * @type {string}
		 * @desc otherRevInfoFormat
		 */
		this.otherRevInfoFormat = getParametersValue(parameters, "otherRevInfoFormat", OtherRevocationInfoFormat.defaultValues("otherRevInfoFormat"));
		/**
		 * @type {Any}
		 * @desc otherRevInfo
		 */
		this.otherRevInfo = getParametersValue(parameters, "otherRevInfo", OtherRevocationInfoFormat.defaultValues("otherRevInfo"));
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
			case "otherRevInfoFormat":
				return "";
			case "otherRevInfo":
				return new Any();
			default:
				throw new Error(`Invalid member name for OtherRevocationInfoFormat class: ${memberName}`);
		}
	}

	//* *********************************************************************************
	/**
	 * Return value of pre-defined ASN.1 schema for current class
	 *
	 * ASN.1 schema:
	 * ```asn1
	 * OtherCertificateFormat ::= SEQUENCE {
	 *    otherRevInfoFormat OBJECT IDENTIFIER,
	 *    otherRevInfo ANY DEFINED BY otherCertFormat }
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
		 * @property {string} [otherRevInfoFormat]
		 * @property {string} [otherRevInfo]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.otherRevInfoFormat || "otherRevInfoFormat") }),
				new Any({ name: (names.otherRevInfo || "otherRevInfo") })
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
			"otherRevInfoFormat",
			"otherRevInfo"
		]);
		// endregion
		
		// region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			OtherRevocationInfoFormat.schema()
		);

		if(asn1.verified === false)
			{throw new Error("Object's schema was not verified against input data for OtherRevocationInfoFormat");}
		// endregion

		// region Get internal properties from parsed schema
		this.otherRevInfoFormat = asn1.result.otherRevInfoFormat.valueBlock.toString();
		this.otherRevInfo = asn1.result.otherRevInfo;
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
				new ObjectIdentifier({ value: this.otherRevInfoFormat }),
				this.otherRevInfo
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
			otherRevInfoFormat: this.otherRevInfoFormat
		};

		if(!(this.otherRevInfo instanceof Any))
			{object.otherRevInfo = this.otherRevInfo.toJSON();}

		return object;
	}
	//* *********************************************************************************
}
//* *************************************************************************************
