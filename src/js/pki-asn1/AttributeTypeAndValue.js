import { clearProps, getParametersValue, isEqualBuffer } from "pvutils";

import { Any, BmpString, CharacterString, compareSchema, GeneralString, GraphicString, IA5String, NumericString, ObjectIdentifier, PrintableString, Sequence, TeletexString, UniversalString, Utf8String, VideotexString, VisibleString } from "./asn1";
import { stringPrep } from "./common";
//* *************************************************************************************
/**
 * Class from RFC5280
 */
export default class AttributeTypeAndValue
{
	//* *********************************************************************************
	/**
	 * Constructor for AttributeTypeAndValue class
	 * @param {Object} [parameters={}]
	 * @param {Object} [parameters.schema] asn1js parsed value to initialize the class from
	 */
	constructor(parameters = {})
	{
		// region Internal properties of the object
		/**
		 * @type {string}
		 * @desc type
		 */
		this.type = getParametersValue(parameters, "type", AttributeTypeAndValue.defaultValues("type"));
		/**
		 * @type {Object}
		 * @desc Value of the AttributeTypeAndValue class
		 */
		this.value = getParametersValue(parameters, "value", AttributeTypeAndValue.defaultValues("value"));
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
			case "type":
				return "";
			case "value":
				return {};
			default:
				throw new Error(`Invalid member name for AttributeTypeAndValue class: ${memberName}`);
		}
	}

	//* *********************************************************************************
	/**
	 * Return value of pre-defined ASN.1 schema for current class
	 *
	 * ASN.1 schema:
	 * ```asn1
	 * AttributeTypeAndValue ::= Sequence {
	 *    type     AttributeType,
	 *    value    AttributeValue }
	 *
	 * AttributeType ::= OBJECT IDENTIFIER
	 *
	 * AttributeValue ::= ANY -- DEFINED BY AttributeType
	 * ```
	 *
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		/**
		 * @type {Object}
		 * @property {string} [blockName] Name for entire block
		 * @property {string} [type] Name for "type" element
		 * @property {string} [value] Name for "value" element
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new Sequence({
			name: (names.blockName || ""),
			value: [
				new ObjectIdentifier({ name: (names.type || "") }),
				new Any({ name: (names.value || "") })
			]
		}));
	}

	//* *********************************************************************************
	static blockName()
	{
		return "AttributeTypeAndValue";
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
			"type",
			"typeValue"
		]);
		// endregion
		
		// region Check the schema is valid
		const asn1 = compareSchema(schema,
			schema,
			AttributeTypeAndValue.schema({
				names: {
					type: "type",
					value: "typeValue"
				}
			})
		);

		if(asn1.verified === false)
			{throw new Error("Object's schema was not verified against input data for AttributeTypeAndValue");}
		// endregion

		// region Get internal properties from parsed schema
		this.type = asn1.result.type.valueBlock.toString();
		// noinspection JSUnresolvedVariable
		this.value = asn1.result.typeValue;
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
				new ObjectIdentifier({ value: this.type }),
				this.value
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
		// eslint-disable-next-line no-underscore-dangle
		const _object = {
			type: this.type
		};

		if(Object.keys(this.value).length !== 0)
			{_object.value = this.value.toJSON();}
		else
			{_object.value = this.value;}

		return _object;
	}

	//* *********************************************************************************
	/**
	 * Compare two AttributeTypeAndValue values, or AttributeTypeAndValue with ArrayBuffer value
	 * @param {(AttributeTypeAndValue|ArrayBuffer)} compareTo The value compare to current
	 * @returns {boolean}
	 */
	isEqual(compareTo)
	{
		const stringBlockNames = [
			Utf8String.blockName(),
			BmpString.blockName(),
			UniversalString.blockName(),
			NumericString.blockName(),
			PrintableString.blockName(),
			TeletexString.blockName(),
			VideotexString.blockName(),
			IA5String.blockName(),
			GraphicString.blockName(),
			VisibleString.blockName(),
			GeneralString.blockName(),
			CharacterString.blockName()
		];

		if(compareTo.constructor.blockName() === AttributeTypeAndValue.blockName())
		{
			if(this.type !== compareTo.type)
				{return false;}

			// region Check we do have both strings
			let isString = [false, false];
			const thisName = this.value.constructor.blockName();

			// eslint-disable-next-line no-restricted-syntax
			for(const name of stringBlockNames)
			{
				if(thisName === name)
				{
					isString[0] = true;
				}

				if(compareTo.value.constructor.blockName() === name)
				{
					isString[1] = true;
				}
			}

			// eslint-disable-next-line no-bitwise
			if(isString[0] ^ isString[1])
				{return false;}

			isString = (isString[0] && isString[1]);
			// endregion

			if(isString)
			{
				const value1 = stringPrep(this.value.valueBlock.value);
				const value2 = stringPrep(compareTo.value.valueBlock.value);

				if(value1.localeCompare(value2) !== 0)
					{return false;}
			}
			else // Comparing as two ArrayBuffers
			if(isEqualBuffer(this.value.valueBeforeDecode, compareTo.value.valueBeforeDecode) === false)
					{return false;}

			return true;
		}

		if(compareTo instanceof ArrayBuffer)
			{return isEqualBuffer(this.value.valueBeforeDecode, compareTo);}

		return false;
	}
	//* *********************************************************************************
}
//* *************************************************************************************
