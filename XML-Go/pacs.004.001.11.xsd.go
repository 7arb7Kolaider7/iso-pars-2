package schema

import (
	"time"
)

// Document ...
type Document *Document

// AccountIdentification4Choice is Unique identification of an account, as assigned by the account servicer, using an identification scheme.
type AccountIdentification4Choice struct {
	IBAN string                         `xml:"IBAN"`
	Othr *GenericAccountIdentification1 `xml:"Othr"`
}

// AccountSchemeName1Choice is Name of the identification scheme, in a free text form.
type AccountSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ActiveCurrencyAndAmountSimpleType ...
type ActiveCurrencyAndAmountSimpleType float64

// ActiveCurrencyAndAmount is A number of monetary units specified in an active currency where the unit of currency is explicit and compliant with ISO 4217.
type ActiveCurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveCurrencyCode is A code allocated to a currency by a Maintenance Agency under an international identification scheme as described in the latest edition of the international standard ISO 4217 "Codes for the representation of currencies and funds".
type ActiveCurrencyCode string

// ActiveOrHistoricCurrencyAndAmountSimpleType ...
type ActiveOrHistoricCurrencyAndAmountSimpleType float64

// ActiveOrHistoricCurrencyAndAmount is A number of monetary units specified in an active or a historic currency where the unit of currency is explicit and compliant with ISO 4217.
type ActiveOrHistoricCurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveOrHistoricCurrencyCode is A code allocated to a currency by a Maintenance Agency under an international identification scheme, as described in the latest edition of the international standard ISO 4217 "Codes for the representation of currencies and funds".
type ActiveOrHistoricCurrencyCode string

// AddressType2Code is Address is the address to which delivery is to take place.
type AddressType2Code string

// AddressType3Choice is Type of address expressed as a proprietary code.
type AddressType3Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// AmendmentInformationDetails14 is Original number of tracking days that has been modified.
type AmendmentInformationDetails14 struct {
	OrgnlMndtId      string                                        `xml:"OrgnlMndtId"`
	OrgnlCdtrSchmeId *PartyIdentification135                       `xml:"OrgnlCdtrSchmeId"`
	OrgnlCdtrAgt     *BranchAndFinancialInstitutionIdentification6 `xml:"OrgnlCdtrAgt"`
	OrgnlCdtrAgtAcct *CashAccount40                                `xml:"OrgnlCdtrAgtAcct"`
	OrgnlDbtr        *PartyIdentification135                       `xml:"OrgnlDbtr"`
	OrgnlDbtrAcct    *CashAccount40                                `xml:"OrgnlDbtrAcct"`
	OrgnlDbtrAgt     *BranchAndFinancialInstitutionIdentification6 `xml:"OrgnlDbtrAgt"`
	OrgnlDbtrAgtAcct *CashAccount40                                `xml:"OrgnlDbtrAgtAcct"`
	OrgnlFnlColltnDt string                                        `xml:"OrgnlFnlColltnDt"`
	OrgnlFrqcy       *Frequency36Choice                            `xml:"OrgnlFrqcy"`
	OrgnlRsn         *MandateSetupReason1Choice                    `xml:"OrgnlRsn"`
	OrgnlTrckgDays   string                                        `xml:"OrgnlTrckgDays"`
}

// AmountType4Choice is Amount of money to be moved between the debtor and creditor, expressed in the currency of the debtor's account, and the currency in which the amount is to be moved.
type AmountType4Choice struct {
	InstdAmt *ActiveOrHistoricCurrencyAndAmount `xml:"InstdAmt"`
	EqvtAmt  *EquivalentAmount2                 `xml:"EqvtAmt"`
}

// AnyBICDec2014Identifier is Code allocated to a financial or non-financial institution by the ISO 9362 Registration Authority, as described in ISO 9362: 2014 - "Banking - Banking telecommunication messages - Business identifier code (BIC)".
type AnyBICDec2014Identifier string

// Authorisation1Choice is Specifies the authorisation, in a free text form.
type Authorisation1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Authorisation1Code is Indicates that a file requires all customer transactions to be authorised or approved.
type Authorisation1Code string

// BICFIDec2014Identifier is Code allocated to a financial institution by the ISO 9362 Registration Authority as described in ISO 9362: 2014 - "Banking - Banking telecommunication messages - Business identifier code (BIC)".
type BICFIDec2014Identifier string

// BaseOneRate is Rate expressed as a decimal, for example, 0.7 is 7/10 and 70%.
type BaseOneRate float64

// BatchBookingIndicator is Identifies whether the sending party requests a single debit or credit entry per individual transaction or a batch entry for the sum of the amounts of all transactions.
type BatchBookingIndicator bool

// BranchAndFinancialInstitutionIdentification6 is Identifies a specific branch of a financial institution.
//
// Usage: This component should be used in case the identification information in the financial institution component does not provide identification up to branch level.
type BranchAndFinancialInstitutionIdentification6 struct {
	FinInstnId *FinancialInstitutionIdentification18 `xml:"FinInstnId"`
	BrnchId    *BranchData3                          `xml:"BrnchId"`
}

// BranchData3 is Information that locates and identifies a specific address, as defined by postal services.
type BranchData3 struct {
	Id      string           `xml:"Id"`
	LEI     string           `xml:"LEI"`
	Nm      string           `xml:"Nm"`
	PstlAdr *PostalAddress24 `xml:"PstlAdr"`
}

// CashAccount40 is Specifies an alternate assumed name for the identification of the account.
type CashAccount40 struct {
	Id   *AccountIdentification4Choice `xml:"Id"`
	Tp   *CashAccountType2Choice       `xml:"Tp"`
	Ccy  string                        `xml:"Ccy"`
	Nm   string                        `xml:"Nm"`
	Prxy *ProxyAccountIdentification1  `xml:"Prxy"`
}

// CashAccountType2Choice is Nature or use of the account in a proprietary form.
type CashAccountType2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CategoryPurpose1Choice is Category purpose, in a proprietary form.
type CategoryPurpose1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ChargeBearerType1Code is Charges are to be applied following the rules agreed in the service level and/or scheme.
type ChargeBearerType1Code string

// Charges7 is Agent that takes the transaction charges or to which the transaction charges are due.
type Charges7 struct {
	Amt *ActiveOrHistoricCurrencyAndAmount            `xml:"Amt"`
	Agt *BranchAndFinancialInstitutionIdentification6 `xml:"Agt"`
}

// ClearingChannel2Code is Payment through internal book transfer.
type ClearingChannel2Code string

// ClearingSystemIdentification2Choice is Identification code for a clearing system, that has not yet been identified in the list of clearing systems.
type ClearingSystemIdentification2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ClearingSystemIdentification3Choice is Clearing system identification in a proprietary form.
type ClearingSystemIdentification3Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ClearingSystemMemberIdentification2 is Identification of a member of a clearing system.
type ClearingSystemMemberIdentification2 struct {
	ClrSysId *ClearingSystemIdentification2Choice `xml:"ClrSysId"`
	MmbId    string                               `xml:"MmbId"`
}

// Contact4 is Preferred method used to reach the contact.
type Contact4 struct {
	NmPrfx    string           `xml:"NmPrfx"`
	Nm        string           `xml:"Nm"`
	PhneNb    string           `xml:"PhneNb"`
	MobNb     string           `xml:"MobNb"`
	FaxNb     string           `xml:"FaxNb"`
	EmailAdr  string           `xml:"EmailAdr"`
	EmailPurp string           `xml:"EmailPurp"`
	JobTitl   string           `xml:"JobTitl"`
	Rspnsblty string           `xml:"Rspnsblty"`
	Dept      string           `xml:"Dept"`
	Othr      []*OtherContact1 `xml:"Othr"`
	PrefrdMtd string           `xml:"PrefrdMtd"`
}

// CountryCode is Code to identify a country, a dependency, or another area of particular geopolitical interest, on the basis of country names obtained from the United Nations (ISO 3166, Alpha-2 code).
type CountryCode string

// CreditDebitCode is Operation is a decrease.
type CreditDebitCode string

// CreditTransferMandateData1 is Reason for the setup of the credit transfer mandate.
//
// Usage:
// The reason will allow the user to distinguish between different mandates for the same creditor.
type CreditTransferMandateData1 struct {
	MndtId       string                     `xml:"MndtId"`
	Tp           *MandateTypeInformation2   `xml:"Tp"`
	DtOfSgntr    string                     `xml:"DtOfSgntr"`
	DtOfVrfctn   string                     `xml:"DtOfVrfctn"`
	ElctrncSgntr []byte                     `xml:"ElctrncSgntr"`
	FrstPmtDt    string                     `xml:"FrstPmtDt"`
	FnlPmtDt     string                     `xml:"FnlPmtDt"`
	Frqcy        *Frequency36Choice         `xml:"Frqcy"`
	Rsn          *MandateSetupReason1Choice `xml:"Rsn"`
}

// CreditTransferTransaction52 is Amount of money to be moved between the debtor and creditor, before deduction of charges, expressed in the currency as ordered by the initiating party.
// Usage: This amount has to be transported unchanged through the transaction chain.
type CreditTransferTransaction52 struct {
	UltmtDbtr         *PartyIdentification135                       `xml:"UltmtDbtr"`
	InitgPty          *PartyIdentification135                       `xml:"InitgPty"`
	Dbtr              *PartyIdentification135                       `xml:"Dbtr"`
	DbtrAcct          *CashAccount40                                `xml:"DbtrAcct"`
	DbtrAgt           *BranchAndFinancialInstitutionIdentification6 `xml:"DbtrAgt"`
	DbtrAgtAcct       *CashAccount40                                `xml:"DbtrAgtAcct"`
	PrvsInstgAgt1     *BranchAndFinancialInstitutionIdentification6 `xml:"PrvsInstgAgt1"`
	PrvsInstgAgt1Acct *CashAccount40                                `xml:"PrvsInstgAgt1Acct"`
	PrvsInstgAgt2     *BranchAndFinancialInstitutionIdentification6 `xml:"PrvsInstgAgt2"`
	PrvsInstgAgt2Acct *CashAccount40                                `xml:"PrvsInstgAgt2Acct"`
	PrvsInstgAgt3     *BranchAndFinancialInstitutionIdentification6 `xml:"PrvsInstgAgt3"`
	PrvsInstgAgt3Acct *CashAccount40                                `xml:"PrvsInstgAgt3Acct"`
	IntrmyAgt1        *BranchAndFinancialInstitutionIdentification6 `xml:"IntrmyAgt1"`
	IntrmyAgt1Acct    *CashAccount40                                `xml:"IntrmyAgt1Acct"`
	IntrmyAgt2        *BranchAndFinancialInstitutionIdentification6 `xml:"IntrmyAgt2"`
	IntrmyAgt2Acct    *CashAccount40                                `xml:"IntrmyAgt2Acct"`
	IntrmyAgt3        *BranchAndFinancialInstitutionIdentification6 `xml:"IntrmyAgt3"`
	IntrmyAgt3Acct    *CashAccount40                                `xml:"IntrmyAgt3Acct"`
	CdtrAgt           *BranchAndFinancialInstitutionIdentification6 `xml:"CdtrAgt"`
	CdtrAgtAcct       *CashAccount40                                `xml:"CdtrAgtAcct"`
	Cdtr              *PartyIdentification135                       `xml:"Cdtr"`
	CdtrAcct          *CashAccount40                                `xml:"CdtrAcct"`
	UltmtCdtr         *PartyIdentification135                       `xml:"UltmtCdtr"`
	InstrForCdtrAgt   []*InstructionForCreditorAgent3               `xml:"InstrForCdtrAgt"`
	InstrForNxtAgt    []*InstructionForNextAgent1                   `xml:"InstrForNxtAgt"`
	Tax               *TaxInformation10                             `xml:"Tax"`
	RmtInf            *RemittanceInformation21                      `xml:"RmtInf"`
	InstdAmt          *ActiveOrHistoricCurrencyAndAmount            `xml:"InstdAmt"`
}

// CreditorReferenceInformation2 is Unique reference, as assigned by the creditor, to unambiguously refer to the payment transaction.
//
// Usage: If available, the initiating party should provide this reference in the structured remittance information, to enable reconciliation by the creditor upon receipt of the amount of money.
//
// If the business context requires the use of a creditor reference or a payment remit identification, and only one identifier can be passed through the end-to-end chain, the creditor's reference or payment remittance identification should be quoted in the end-to-end transaction identification.
type CreditorReferenceInformation2 struct {
	Tp  *CreditorReferenceType2 `xml:"Tp"`
	Ref string                  `xml:"Ref"`
}

// CreditorReferenceType1Choice is Creditor reference type, in a proprietary form.
type CreditorReferenceType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CreditorReferenceType2 is Entity that assigns the credit reference type.
type CreditorReferenceType2 struct {
	CdOrPrtry *CreditorReferenceType1Choice `xml:"CdOrPrtry"`
	Issr      string                        `xml:"Issr"`
}

// DateAndDateTime2Choice is Specified date and time.
type DateAndDateTime2Choice struct {
	Dt   string `xml:"Dt"`
	DtTm string `xml:"DtTm"`
}

// DateAndPlaceOfBirth1 is Country where a person was born.
type DateAndPlaceOfBirth1 struct {
	BirthDt     string `xml:"BirthDt"`
	PrvcOfBirth string `xml:"PrvcOfBirth"`
	CityOfBirth string `xml:"CityOfBirth"`
	CtryOfBirth string `xml:"CtryOfBirth"`
}

// DatePeriod2 is End date of the range.
type DatePeriod2 struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// DecimalNumber is Number of objects represented as a decimal number, for example 0.75 or 45.6.
type DecimalNumber float64

// DiscountAmountAndType1 is Amount of money, which has been typed.
type DiscountAmountAndType1 struct {
	Tp  *DiscountAmountType1Choice         `xml:"Tp"`
	Amt *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
}

// DiscountAmountType1Choice is Specifies the amount type, in a free-text form.
type DiscountAmountType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// DocumentAdjustment1 is Provides further details on the document adjustment.
type DocumentAdjustment1 struct {
	Amt       *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Rsn       string                             `xml:"Rsn"`
	AddtlInf  string                             `xml:"AddtlInf"`
}

// DocumentLineIdentification1 is Date associated with the referred document line.
type DocumentLineIdentification1 struct {
	Tp     *DocumentLineType1 `xml:"Tp"`
	Nb     string             `xml:"Nb"`
	RltdDt string             `xml:"RltdDt"`
}

// DocumentLineInformation1 is Provides details on the amounts of the document line.
type DocumentLineInformation1 struct {
	Id   []*DocumentLineIdentification1 `xml:"Id"`
	Desc string                         `xml:"Desc"`
	Amt  *RemittanceAmount3             `xml:"Amt"`
}

// DocumentLineType1 is Identification of the issuer of the reference document line identificationtype.
type DocumentLineType1 struct {
	CdOrPrtry *DocumentLineType1Choice `xml:"CdOrPrtry"`
	Issr      string                   `xml:"Issr"`
}

// DocumentLineType1Choice is Proprietary identification of the type of the remittance document.
type DocumentLineType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// DocumentType3Code is Document is a structured communication reference provided by the creditor to identify the referred transaction.
type DocumentType3Code string

// DocumentType6Code is Document is a purchase order.
type DocumentType6Code string

// EquivalentAmount2 is Specifies the currency of the to be transferred amount, which is different from the currency of the debtor's account.
type EquivalentAmount2 struct {
	Amt      *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CcyOfTrf string                             `xml:"CcyOfTrf"`
}

// Exact2NumericText is Specifies a numeric string with an exact length of 2 digits.
type Exact2NumericText string

// Exact4AlphaNumericText is Specifies an alphanumeric string with a length of 4 characters.
type Exact4AlphaNumericText string

// ExternalAccountIdentification1Code is Specifies the external account identification scheme name code in the format of character string with a maximum length of 4 characters.
// The list of valid codes is an external code list published separately.
// External code sets can be downloaded from www.iso20022.org.
type ExternalAccountIdentification1Code string

// ExternalCashAccountType1Code is Specifies the nature, or use, of the cash account in the format of character string with a maximum length of 4 characters.
// The list of valid codes is an external code list published separately.
// External code sets can be downloaded from www.iso20022.org.
type ExternalCashAccountType1Code string

// ExternalCashClearingSystem1Code is Specifies the cash clearing system, as published in an external cash clearing system code list.
// External code sets can be downloaded from www.iso20022.org.
type ExternalCashClearingSystem1Code string

// ExternalCategoryPurpose1Code is Specifies the category purpose, as published in an external category purpose code list.
// External code sets can be downloaded from www.iso20022.org.
type ExternalCategoryPurpose1Code string

// ExternalClearingSystemIdentification1Code is Specifies the clearing system identification code, as published in an external clearing system identification code list.
// External code sets can be downloaded from www.iso20022.org.
type ExternalClearingSystemIdentification1Code string

// ExternalCreditorAgentInstruction1Code is Specifies further instructions concerning the processing of a payment instruction, as provided to the creditor agent.
type ExternalCreditorAgentInstruction1Code string

// ExternalDiscountAmountType1Code is Specifies the nature, or use, of the amount in the format of character string with a maximum length of 4 characters.
// The list of valid codes is an external code list published separately.
// External code sets can be downloaded from www.iso20022.org.
type ExternalDiscountAmountType1Code string

// ExternalDocumentLineType1Code is Specifies the document line type as published in an external document type code list.
type ExternalDocumentLineType1Code string

// ExternalFinancialInstitutionIdentification1Code is Specifies the external financial institution identification scheme name code in the format of character string with a maximum length of 4 characters.
// The list of valid codes is an external code list published separately.
// External code sets can be downloaded from www.iso20022.org.
type ExternalFinancialInstitutionIdentification1Code string

// ExternalGarnishmentType1Code is Specifies the garnishment type as published in an external document type code list.
type ExternalGarnishmentType1Code string

// ExternalLocalInstrument1Code is Specifies the external local instrument code in the format of character string with a maximum length of 35 characters.
// The list of valid codes is an external code list published separately.
// External code sets can be downloaded from www.iso20022.org.
type ExternalLocalInstrument1Code string

// ExternalMandateSetupReason1Code is Specifies the external mandate setup reason code in the format of character string with a maximum length of 4 characters.
// External code sets can be downloaded from www.iso20022.org.
type ExternalMandateSetupReason1Code string

// ExternalOrganisationIdentification1Code is Specifies the external organisation identification scheme name code in the format of character string with a maximum length of 4 characters.
// The list of valid codes is an external code list published separately.
// External code sets can be downloaded from www.iso20022.org.
type ExternalOrganisationIdentification1Code string

// ExternalPersonIdentification1Code is Specifies the external person identification scheme name code in the format of character string with a maximum length of 4 characters.
// The list of valid codes is an external code list published separately.
// External code sets can be downloaded from www.iso20022.org.
type ExternalPersonIdentification1Code string

// ExternalProxyAccountType1Code is Specifies the external proxy account type code, as published in the proxy account type external code set.
// External code sets can be downloaded from www.iso20022.org.
type ExternalProxyAccountType1Code string

// ExternalPurpose1Code is Specifies the external purpose code in the format of character string with a maximum length of 4 characters.
// The list of valid codes is an external code list published separately.
// External code sets can be downloaded from www.iso20022.org.
type ExternalPurpose1Code string

// ExternalReturnReason1Code is Specifies the return reason, as published in an external return reason code list.
// External code sets can be downloaded from www.iso20022.org.
type ExternalReturnReason1Code string

// ExternalServiceLevel1Code is Specifies the external service level code in the format of character string with a maximum length of 4 characters.
// The list of valid codes is an external code list published separately.
// External code sets can be downloaded from www.iso20022.org.
type ExternalServiceLevel1Code string

// ExternalTaxAmountType1Code is Specifies the nature, or use, of the amount in the format of character string with a maximum length of 4 characters.
// The list of valid codes is an external code list published separately.
// External code sets can be downloaded from www.iso20022.org.
type ExternalTaxAmountType1Code string

// FinancialIdentificationSchemeName1Choice is Name of the identification scheme, in a free text form.
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// FinancialInstitutionIdentification18 is Unique identification of an agent, as assigned by an institution, using an identification scheme.
type FinancialInstitutionIdentification18 struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	LEI         string                               `xml:"LEI"`
	Nm          string                               `xml:"Nm"`
	PstlAdr     *PostalAddress24                     `xml:"PstlAdr"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
}

// Frequency36Choice is Specifies a frequency in terms of an exact point in time or moment within a specified period type.
type Frequency36Choice struct {
	Tp     string               `xml:"Tp"`
	Prd    *FrequencyPeriod1    `xml:"Prd"`
	PtInTm *FrequencyAndMoment1 `xml:"PtInTm"`
}

// Frequency6Code is Event takes place every two weeks.
type Frequency6Code string

// FrequencyAndMoment1 is Further information on the exact point in time the event should take place.
type FrequencyAndMoment1 struct {
	Tp     string `xml:"Tp"`
	PtInTm string `xml:"PtInTm"`
}

// FrequencyPeriod1 is Number of instructions to be created and processed during the specified period.
type FrequencyPeriod1 struct {
	Tp        string  `xml:"Tp"`
	CntPerPrd float64 `xml:"CntPerPrd"`
}

// Garnishment3 is Indicates if the employment of the person to whom the garnishment applies (that is, the ultimate debtor) has been terminated.
type Garnishment3 struct {
	Tp                *GarnishmentType1                  `xml:"Tp"`
	Grnshee           *PartyIdentification135            `xml:"Grnshee"`
	GrnshmtAdmstr     *PartyIdentification135            `xml:"GrnshmtAdmstr"`
	RefNb             string                             `xml:"RefNb"`
	Dt                string                             `xml:"Dt"`
	RmtdAmt           *ActiveOrHistoricCurrencyAndAmount `xml:"RmtdAmt"`
	FmlyMdclInsrncInd bool                               `xml:"FmlyMdclInsrncInd"`
	MplyeeTermntnInd  bool                               `xml:"MplyeeTermntnInd"`
}

// GarnishmentType1 is Identification of the issuer of the garnishment type.
type GarnishmentType1 struct {
	CdOrPrtry *GarnishmentType1Choice `xml:"CdOrPrtry"`
	Issr      string                  `xml:"Issr"`
}

// GarnishmentType1Choice is Proprietary identification of the type of garnishment.
type GarnishmentType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// GenericAccountIdentification1 is Entity that assigns the identification.
type GenericAccountIdentification1 struct {
	Id      string                    `xml:"Id"`
	SchmeNm *AccountSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                    `xml:"Issr"`
}

// GenericFinancialIdentification1 is Entity that assigns the identification.
type GenericFinancialIdentification1 struct {
	Id      string                                    `xml:"Id"`
	SchmeNm *FinancialIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                    `xml:"Issr"`
}

// GenericIdentification30 is Short textual description of the scheme.
type GenericIdentification30 struct {
	Id      string `xml:"Id"`
	Issr    string `xml:"Issr"`
	SchmeNm string `xml:"SchmeNm"`
}

// GenericOrganisationIdentification1 is Entity that assigns the identification.
type GenericOrganisationIdentification1 struct {
	Id      string                                       `xml:"Id"`
	SchmeNm *OrganisationIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                       `xml:"Issr"`
}

// GenericPersonIdentification1 is Entity that assigns the identification.
type GenericPersonIdentification1 struct {
	Id      string                                 `xml:"Id"`
	SchmeNm *PersonIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                 `xml:"Issr"`
}

// GroupHeader99 is Agent that is instructed by the previous party in the chain to carry out the (set of) instruction(s).
// Usage: The instructed agent is the party receiving the return message and not the party that received the original instruction that is being returned.
type GroupHeader99 struct {
	MsgId                 string                                        `xml:"MsgId"`
	CreDtTm               string                                        `xml:"CreDtTm"`
	Authstn               []*Authorisation1Choice                       `xml:"Authstn"`
	BtchBookg             bool                                          `xml:"BtchBookg"`
	NbOfTxs               string                                        `xml:"NbOfTxs"`
	CtrlSum               float64                                       `xml:"CtrlSum"`
	GrpRtr                bool                                          `xml:"GrpRtr"`
	TtlRtrdIntrBkSttlmAmt *ActiveCurrencyAndAmount                      `xml:"TtlRtrdIntrBkSttlmAmt"`
	IntrBkSttlmDt         string                                        `xml:"IntrBkSttlmDt"`
	SttlmInf              *SettlementInstruction11                      `xml:"SttlmInf"`
	PmtTpInf              *PaymentTypeInformation28                     `xml:"PmtTpInf"`
	InstgAgt              *BranchAndFinancialInstitutionIdentification6 `xml:"InstgAgt"`
	InstdAgt              *BranchAndFinancialInstitutionIdentification6 `xml:"InstdAgt"`
}

// IBAN2007Identifier is An identifier used internationally by financial institutions to uniquely identify the account of a customer at a financial institution, as described in the latest edition of the international standard ISO 13616: 2007 - "Banking and related financial services - International Bank Account Number (IBAN)".
type IBAN2007Identifier string

// ISODate is A particular point in the progression of time in a calendar year expressed in the YYYY-MM-DD format. This representation is defined in "XML Schema Part 2: Datatypes Second Edition - W3C Recommendation 28 October 2004" which is aligned with ISO 8601.
type ISODate string

// ISODateTime is A particular point in the progression of time defined by a mandatory date and a mandatory time component, expressed in either UTC time format (YYYY-MM-DDThh:mm:ss.sssZ), local time with UTC offset format (YYYY-MM-DDThh:mm:ss.sss+/-hh:mm), or local time format (YYYY-MM-DDThh:mm:ss.sss). These representations are defined in "XML Schema Part 2: Datatypes Second Edition - W3C Recommendation 28 October 2004" which is aligned with ISO 8601.
// Note on the time format:
// 1) beginning / end of calendar day
// 00:00:00 = the beginning of a calendar day
// 24:00:00 = the end of a calendar day
// 2) fractions of second in time format
// Decimal fractions of seconds may be included. In this case, the involved parties shall agree on the maximum number of digits that are allowed.
type ISODateTime string

// ISOTime is A particular point in the progression of time in a calendar day expressed in either UTC time format (hh:mm:ss.sssZ), local time with UTC offset format (hh:mm:ss.sss+/-hh:mm), or local time format (hh:mm:ss.sss). These representations are defined in "XML Schema Part 2: Datatypes Second Edition - W3C Recommendation 28 October 2004" which is aligned with ISO 8601.
// Note on the time format:
// 1) beginning / end of calendar day
// 00:00:00 = the beginning of a calendar day
// 24:00:00 = the end of a calendar day
// 2) fractions of second in time format
// Decimal fractions of seconds may be included. In this case, the involved parties shall agree on the maximum number of digits that are allowed.
type ISOTime time.Time

// ISOYear is Year represented by YYYY (ISO 8601).
type ISOYear string

// Instruction4Code is Please advise/contact next agent by the most efficient means of telecommunication.
type Instruction4Code string

// InstructionForCreditorAgent3 is Further information complementing the coded instruction or instruction to the creditor's agent that is bilaterally agreed or specific to a user community.
type InstructionForCreditorAgent3 struct {
	Cd       string `xml:"Cd"`
	InstrInf string `xml:"InstrInf"`
}

// InstructionForNextAgent1 is Further information complementing the coded instruction or instruction to the next agent that is bilaterally agreed or specific to a user community.
type InstructionForNextAgent1 struct {
	Cd       string `xml:"Cd"`
	InstrInf string `xml:"InstrInf"`
}

// LEIIdentifier is Legal Entity Identifier is a code allocated to a party as described in ISO 17442 "Financial Services - Legal Entity Identifier (LEI)".
type LEIIdentifier string

// LocalInstrument2Choice is Specifies the local instrument, as a proprietary code.
type LocalInstrument2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// MandateClassification1Choice is Category purpose, in a proprietary form.
type MandateClassification1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// MandateClassification1Code is Direct debit amount is variable.
type MandateClassification1Code string

// MandateRelatedData2Choice is Specific credit transfer mandate data.
type MandateRelatedData2Choice struct {
	DrctDbtMndt *MandateRelatedInformation15 `xml:"DrctDbtMndt"`
	CdtTrfMndt  *CreditTransferMandateData1  `xml:"CdtTrfMndt"`
}

// MandateRelatedInformation15 is Specifies the number of days the direct debit instruction must be tracked.
type MandateRelatedInformation15 struct {
	MndtId        string                         `xml:"MndtId"`
	DtOfSgntr     string                         `xml:"DtOfSgntr"`
	AmdmntInd     bool                           `xml:"AmdmntInd"`
	AmdmntInfDtls *AmendmentInformationDetails14 `xml:"AmdmntInfDtls"`
	ElctrncSgntr  string                         `xml:"ElctrncSgntr"`
	FrstColltnDt  string                         `xml:"FrstColltnDt"`
	FnlColltnDt   string                         `xml:"FnlColltnDt"`
	Frqcy         *Frequency36Choice             `xml:"Frqcy"`
	Rsn           *MandateSetupReason1Choice     `xml:"Rsn"`
	TrckgDays     string                         `xml:"TrckgDays"`
}

// MandateSetupReason1Choice is Reason for the mandate setup, in a proprietary form.
type MandateSetupReason1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// MandateTypeInformation2 is Type of direct debit instruction.
type MandateTypeInformation2 struct {
	SvcLvl    *ServiceLevel8Choice          `xml:"SvcLvl"`
	LclInstrm *LocalInstrument2Choice       `xml:"LclInstrm"`
	CtgyPurp  *CategoryPurpose1Choice       `xml:"CtgyPurp"`
	Clssfctn  *MandateClassification1Choice `xml:"Clssfctn"`
}

// Max1025Text is Specifies a character string with a maximum length of 1025 characters.
type Max1025Text string

// Max105Text is Specifies a character string with a maximum length of 105 characters.
type Max105Text string

// Max10KBinary is Binary data of 10K maximum.
type Max10KBinary []byte

// Max128Text is Specifies a character string with a maximum length of 128 characters.
type Max128Text string

// Max140Text is Specifies a character string with a maximum length of 140 characters.
type Max140Text string

// Max15NumericText is Specifies a numeric string with a maximum length of 15 digits.
type Max15NumericText string

// Max16Text is Specifies a character string with a maximum length of 16 characters.
type Max16Text string

// Max2048Text is Specifies a character string with a maximum length of 2048 characters.
type Max2048Text string

// Max34Text is Specifies a character string with a maximum length of 34 characters.
type Max34Text string

// Max350Text is Specifies a character string with a maximum length of 350 characters.
type Max350Text string

// Max35Text is Specifies a character string with a maximum length of 35 characters.
type Max35Text string

// Max4Text is Specifies a character string with a maximum length of 4 characters.
type Max4Text string

// Max70Text is Specifies a character string with a maximum length of 70characters.
type Max70Text string

// NamePrefix2Code is Title of the person is gender neutral (Mx).
type NamePrefix2Code string

// Number is Number of objects represented as an integer.
type Number float64

// OrganisationIdentification29 is Unique identification of an organisation, as assigned by an institution, using an identification scheme.
type OrganisationIdentification29 struct {
	AnyBIC string                                `xml:"AnyBIC"`
	LEI    string                                `xml:"LEI"`
	Othr   []*GenericOrganisationIdentification1 `xml:"Othr"`
}

// OrganisationIdentificationSchemeName1Choice is Name of the identification scheme, in a free text form.
type OrganisationIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// OriginalGroupHeader18 is Provides detailed information on the return reason.
type OriginalGroupHeader18 struct {
	OrgnlMsgId   string                  `xml:"OrgnlMsgId"`
	OrgnlMsgNmId string                  `xml:"OrgnlMsgNmId"`
	OrgnlCreDtTm string                  `xml:"OrgnlCreDtTm"`
	RtrRsnInf    []*PaymentReturnReason6 `xml:"RtrRsnInf"`
}

// OriginalGroupInformation29 is Original date and time at which the message was created.
type OriginalGroupInformation29 struct {
	OrgnlMsgId   string `xml:"OrgnlMsgId"`
	OrgnlMsgNmId string `xml:"OrgnlMsgNmId"`
	OrgnlCreDtTm string `xml:"OrgnlCreDtTm"`
}

// OriginalTransactionReference36 is Provides information on the underlying customer credit transfer for which cover is provided.
type OriginalTransactionReference36 struct {
	IntrBkSttlmAmt     *ActiveOrHistoricCurrencyAndAmount            `xml:"IntrBkSttlmAmt"`
	Amt                *AmountType4Choice                            `xml:"Amt"`
	IntrBkSttlmDt      string                                        `xml:"IntrBkSttlmDt"`
	ReqdColltnDt       string                                        `xml:"ReqdColltnDt"`
	ReqdExctnDt        *DateAndDateTime2Choice                       `xml:"ReqdExctnDt"`
	CdtrSchmeId        *PartyIdentification135                       `xml:"CdtrSchmeId"`
	SttlmInf           *SettlementInstruction11                      `xml:"SttlmInf"`
	PmtTpInf           *PaymentTypeInformation27                     `xml:"PmtTpInf"`
	PmtMtd             string                                        `xml:"PmtMtd"`
	MndtRltdInf        *MandateRelatedData2Choice                    `xml:"MndtRltdInf"`
	RmtInf             *RemittanceInformation21                      `xml:"RmtInf"`
	UltmtDbtr          *Party40Choice                                `xml:"UltmtDbtr"`
	Dbtr               *Party40Choice                                `xml:"Dbtr"`
	DbtrAcct           *CashAccount40                                `xml:"DbtrAcct"`
	DbtrAgt            *BranchAndFinancialInstitutionIdentification6 `xml:"DbtrAgt"`
	DbtrAgtAcct        *CashAccount40                                `xml:"DbtrAgtAcct"`
	CdtrAgt            *BranchAndFinancialInstitutionIdentification6 `xml:"CdtrAgt"`
	CdtrAgtAcct        *CashAccount40                                `xml:"CdtrAgtAcct"`
	Cdtr               *Party40Choice                                `xml:"Cdtr"`
	CdtrAcct           *CashAccount40                                `xml:"CdtrAcct"`
	UltmtCdtr          *Party40Choice                                `xml:"UltmtCdtr"`
	Purp               *Purpose2Choice                               `xml:"Purp"`
	UndrlygCstmrCdtTrf *CreditTransferTransaction52                  `xml:"UndrlygCstmrCdtTrf"`
}

// OtherContact1 is Communication value such as phone number or email address.
type OtherContact1 struct {
	ChanlTp string `xml:"ChanlTp"`
	Id      string `xml:"Id"`
}

// Party38Choice is Unique and unambiguous identification of a person, for example a passport.
type Party38Choice struct {
	OrgId  *OrganisationIdentification29 `xml:"OrgId"`
	PrvtId *PersonIdentification13       `xml:"PrvtId"`
}

// Party40Choice is Identification of a financial institution.
type Party40Choice struct {
	Pty *PartyIdentification135                       `xml:"Pty"`
	Agt *BranchAndFinancialInstitutionIdentification6 `xml:"Agt"`
}

// PartyIdentification135 is Set of elements used to indicate how to contact the party.
type PartyIdentification135 struct {
	Nm        string           `xml:"Nm"`
	PstlAdr   *PostalAddress24 `xml:"PstlAdr"`
	Id        *Party38Choice   `xml:"Id"`
	CtryOfRes string           `xml:"CtryOfRes"`
	CtctDtls  *Contact4        `xml:"CtctDtls"`
}

// PaymentMethod4Code is Transfer of an amount of money in the books of the account servicer. An advice should be sent back to the account owner.
type PaymentMethod4Code string

// PaymentReturnReason6 is Further details on the return reason.
type PaymentReturnReason6 struct {
	Orgtr    *PartyIdentification135 `xml:"Orgtr"`
	Rsn      *ReturnReason5Choice    `xml:"Rsn"`
	AddtlInf []string                `xml:"AddtlInf"`
}

// PaymentReturnV11 is Additional information that cannot be captured in the structured elements and/or any other specific block.
type PaymentReturnV11 struct {
	GrpHdr      *GroupHeader99           `xml:"GrpHdr"`
	OrgnlGrpInf *OriginalGroupHeader18   `xml:"OrgnlGrpInf"`
	TxInf       []*PaymentTransaction133 `xml:"TxInf"`
	SplmtryData []*SupplementaryData1    `xml:"SplmtryData"`
}

// PaymentTransaction133 is Additional information that cannot be captured in the structured elements and/or any other specific block.
type PaymentTransaction133 struct {
	RtrId               string                                        `xml:"RtrId"`
	OrgnlGrpInf         *OriginalGroupInformation29                   `xml:"OrgnlGrpInf"`
	OrgnlInstrId        string                                        `xml:"OrgnlInstrId"`
	OrgnlEndToEndId     string                                        `xml:"OrgnlEndToEndId"`
	OrgnlTxId           string                                        `xml:"OrgnlTxId"`
	OrgnlUETR           string                                        `xml:"OrgnlUETR"`
	OrgnlClrSysRef      string                                        `xml:"OrgnlClrSysRef"`
	OrgnlIntrBkSttlmAmt *ActiveOrHistoricCurrencyAndAmount            `xml:"OrgnlIntrBkSttlmAmt"`
	OrgnlIntrBkSttlmDt  string                                        `xml:"OrgnlIntrBkSttlmDt"`
	PmtTpInf            *PaymentTypeInformation28                     `xml:"PmtTpInf"`
	RtrdIntrBkSttlmAmt  *ActiveCurrencyAndAmount                      `xml:"RtrdIntrBkSttlmAmt"`
	IntrBkSttlmDt       string                                        `xml:"IntrBkSttlmDt"`
	SttlmPrty           string                                        `xml:"SttlmPrty"`
	SttlmTmIndctn       *SettlementDateTimeIndication1                `xml:"SttlmTmIndctn"`
	SttlmTmReq          *SettlementTimeRequest2                       `xml:"SttlmTmReq"`
	RtrdInstdAmt        *ActiveOrHistoricCurrencyAndAmount            `xml:"RtrdInstdAmt"`
	XchgRate            float64                                       `xml:"XchgRate"`
	CompstnAmt          *ActiveOrHistoricCurrencyAndAmount            `xml:"CompstnAmt"`
	ChrgBr              string                                        `xml:"ChrgBr"`
	ChrgsInf            []*Charges7                                   `xml:"ChrgsInf"`
	ClrSysRef           string                                        `xml:"ClrSysRef"`
	InstgAgt            *BranchAndFinancialInstitutionIdentification6 `xml:"InstgAgt"`
	InstdAgt            *BranchAndFinancialInstitutionIdentification6 `xml:"InstdAgt"`
	RtrChain            *TransactionParties10                         `xml:"RtrChain"`
	RtrRsnInf           []*PaymentReturnReason6                       `xml:"RtrRsnInf"`
	OrgnlTxRef          *OriginalTransactionReference36               `xml:"OrgnlTxRef"`
	SplmtryData         []*SupplementaryData1                         `xml:"SplmtryData"`
}

// PaymentTypeInformation27 is Specifies the high level purpose of the instruction based on a set of pre-defined categories.
// Usage: This is used by the initiating party to provide information concerning the processing of the payment. It is likely to trigger special processing by any of the agents involved in the payment chain.
type PaymentTypeInformation27 struct {
	InstrPrty string                  `xml:"InstrPrty"`
	ClrChanl  string                  `xml:"ClrChanl"`
	SvcLvl    []*ServiceLevel8Choice  `xml:"SvcLvl"`
	LclInstrm *LocalInstrument2Choice `xml:"LclInstrm"`
	SeqTp     string                  `xml:"SeqTp"`
	CtgyPurp  *CategoryPurpose1Choice `xml:"CtgyPurp"`
}

// PaymentTypeInformation28 is Specifies the high level purpose of the instruction based on a set of pre-defined categories.
// Usage: This is used by the initiating party to provide information concerning the processing of the payment. It is likely to trigger special processing by any of the agents involved in the payment chain.
type PaymentTypeInformation28 struct {
	InstrPrty string                  `xml:"InstrPrty"`
	ClrChanl  string                  `xml:"ClrChanl"`
	SvcLvl    []*ServiceLevel8Choice  `xml:"SvcLvl"`
	LclInstrm *LocalInstrument2Choice `xml:"LclInstrm"`
	CtgyPurp  *CategoryPurpose1Choice `xml:"CtgyPurp"`
}

// PercentageRate is Rate expressed as a percentage, that is, in hundredths, for example, 0.7 is 7/10 of a percent, and 7.0 is 7%.
type PercentageRate float64

// PersonIdentification13 is Unique identification of a person, as assigned by an institution, using an identification scheme.
type PersonIdentification13 struct {
	DtAndPlcOfBirth *DateAndPlaceOfBirth1           `xml:"DtAndPlcOfBirth"`
	Othr            []*GenericPersonIdentification1 `xml:"Othr"`
}

// PersonIdentificationSchemeName1Choice is Name of the identification scheme, in a free text form.
type PersonIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// PhoneNumber is The collection of information which identifies a specific phone or FAX number as defined by telecom services.
// It consists of a "+" followed by the country code (from 1 to 3 characters) then a "-" and finally, any combination of numbers, "(", ")", "+" and "-" (up to 30 characters).
type PhoneNumber string

// PostalAddress24 is Information that locates and identifies a specific address, as defined by postal services, presented in free format text.
type PostalAddress24 struct {
	AdrTp       *AddressType3Choice `xml:"AdrTp"`
	Dept        string              `xml:"Dept"`
	SubDept     string              `xml:"SubDept"`
	StrtNm      string              `xml:"StrtNm"`
	BldgNb      string              `xml:"BldgNb"`
	BldgNm      string              `xml:"BldgNm"`
	Flr         string              `xml:"Flr"`
	PstBx       string              `xml:"PstBx"`
	Room        string              `xml:"Room"`
	PstCd       string              `xml:"PstCd"`
	TwnNm       string              `xml:"TwnNm"`
	TwnLctnNm   string              `xml:"TwnLctnNm"`
	DstrctNm    string              `xml:"DstrctNm"`
	CtrySubDvsn string              `xml:"CtrySubDvsn"`
	Ctry        string              `xml:"Ctry"`
	AdrLine     []string            `xml:"AdrLine"`
}

// PreferredContactMethod1Code is Preferred method used to reach the contact is per mobile or cell phone.
type PreferredContactMethod1Code string

// Priority2Code is Priority level is normal.
type Priority2Code string

// Priority3Code is Priority level is normal.
type Priority3Code string

// ProxyAccountIdentification1 is Identification used to indicate the account identification under another specified name.
type ProxyAccountIdentification1 struct {
	Tp *ProxyAccountType1Choice `xml:"Tp"`
	Id string                   `xml:"Id"`
}

// ProxyAccountType1Choice is Name of the identification scheme, in a free text form.
type ProxyAccountType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Purpose2Choice is Purpose, in a proprietary form.
type Purpose2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ReferredDocumentInformation7 is Set of elements used to provide the content of the referred document line.
type ReferredDocumentInformation7 struct {
	Tp       *ReferredDocumentType4      `xml:"Tp"`
	Nb       string                      `xml:"Nb"`
	RltdDt   string                      `xml:"RltdDt"`
	LineDtls []*DocumentLineInformation1 `xml:"LineDtls"`
}

// ReferredDocumentType3Choice is Proprietary identification of the type of the remittance document.
type ReferredDocumentType3Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ReferredDocumentType4 is Identification of the issuer of the reference document type.
type ReferredDocumentType4 struct {
	CdOrPrtry *ReferredDocumentType3Choice `xml:"CdOrPrtry"`
	Issr      string                       `xml:"Issr"`
}

// RemittanceAmount2 is Amount of money remitted for the referred document.
type RemittanceAmount2 struct {
	DuePyblAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"DuePyblAmt"`
	DscntApldAmt      []*DiscountAmountAndType1          `xml:"DscntApldAmt"`
	CdtNoteAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"CdtNoteAmt"`
	TaxAmt            []*TaxAmountAndType1               `xml:"TaxAmt"`
	AdjstmntAmtAndRsn []*DocumentAdjustment1             `xml:"AdjstmntAmtAndRsn"`
	RmtdAmt           *ActiveOrHistoricCurrencyAndAmount `xml:"RmtdAmt"`
}

// RemittanceAmount3 is Amount of money remitted.
type RemittanceAmount3 struct {
	DuePyblAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"DuePyblAmt"`
	DscntApldAmt      []*DiscountAmountAndType1          `xml:"DscntApldAmt"`
	CdtNoteAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"CdtNoteAmt"`
	TaxAmt            []*TaxAmountAndType1               `xml:"TaxAmt"`
	AdjstmntAmtAndRsn []*DocumentAdjustment1             `xml:"AdjstmntAmtAndRsn"`
	RmtdAmt           *ActiveOrHistoricCurrencyAndAmount `xml:"RmtdAmt"`
}

// RemittanceInformation21 is Information supplied to enable the matching/reconciliation of an entry with the items that the payment is intended to settle, such as commercial invoices in an accounts' receivable system, in a structured form.
type RemittanceInformation21 struct {
	Ustrd []string                             `xml:"Ustrd"`
	Strd  []*StructuredRemittanceInformation17 `xml:"Strd"`
}

// ReturnReason5Choice is Reason for the return, in a proprietary form.
type ReturnReason5Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SequenceType3Code is Collection used to re-present previously reversed or returned direct debit transactions.
type SequenceType3Code string

// ServiceLevel8Choice is Specifies a pre-agreed service or level of service between the parties, as a proprietary code.
type ServiceLevel8Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SettlementDateTimeIndication1 is Date and time at which a payment has been credited at the transaction administrator. In the case of TARGET, the date and time at which the payment has been credited at the receiving central bank, expressed in Central European Time (CET).
type SettlementDateTimeIndication1 struct {
	DbtDtTm string `xml:"DbtDtTm"`
	CdtDtTm string `xml:"CdtDtTm"`
}

// SettlementInstruction11 is Unambiguous identification of the account of the third reimbursement agent account at its servicing agent in the payment chain.
type SettlementInstruction11 struct {
	SttlmMtd             string                                        `xml:"SttlmMtd"`
	SttlmAcct            *CashAccount40                                `xml:"SttlmAcct"`
	ClrSys               *ClearingSystemIdentification3Choice          `xml:"ClrSys"`
	InstgRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification6 `xml:"InstgRmbrsmntAgt"`
	InstgRmbrsmntAgtAcct *CashAccount40                                `xml:"InstgRmbrsmntAgtAcct"`
	InstdRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification6 `xml:"InstdRmbrsmntAgt"`
	InstdRmbrsmntAgtAcct *CashAccount40                                `xml:"InstdRmbrsmntAgtAcct"`
	ThrdRmbrsmntAgt      *BranchAndFinancialInstitutionIdentification6 `xml:"ThrdRmbrsmntAgt"`
	ThrdRmbrsmntAgtAcct  *CashAccount40                                `xml:"ThrdRmbrsmntAgtAcct"`
}

// SettlementMethod1Code is Settlement is done through a payment clearing system.
type SettlementMethod1Code string

// SettlementTimeRequest2 is Time by when the payment must be settled to avoid rejection.
type SettlementTimeRequest2 struct {
	CLSTm  time.Time `xml:"CLSTm"`
	TillTm time.Time `xml:"TillTm"`
	FrTm   time.Time `xml:"FrTm"`
	RjctTm time.Time `xml:"RjctTm"`
}

// StructuredRemittanceInformation17 is Additional information, in free text form, to complement the structured remittance information.
type StructuredRemittanceInformation17 struct {
	RfrdDocInf  []*ReferredDocumentInformation7 `xml:"RfrdDocInf"`
	RfrdDocAmt  *RemittanceAmount2              `xml:"RfrdDocAmt"`
	CdtrRefInf  *CreditorReferenceInformation2  `xml:"CdtrRefInf"`
	Invcr       *PartyIdentification135         `xml:"Invcr"`
	Invcee      *PartyIdentification135         `xml:"Invcee"`
	TaxRmt      *TaxData1                       `xml:"TaxRmt"`
	GrnshmtRmt  *Garnishment3                   `xml:"GrnshmtRmt"`
	AddtlRmtInf []string                        `xml:"AddtlRmtInf"`
}

// SupplementaryData1 is Technical element wrapping the supplementary data.
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 is Technical component that contains the validated supplementary data information. This technical envelope allows to segregate the supplementary data information from any other information.
type SupplementaryDataEnvelope1 struct {
}

// TaxAmount3 is Set of elements used to provide details on the tax period and amount.
type TaxAmount3 struct {
	Rate         float64                            `xml:"Rate"`
	TaxblBaseAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TaxblBaseAmt"`
	TtlAmt       *ActiveOrHistoricCurrencyAndAmount `xml:"TtlAmt"`
	Dtls         []*TaxRecordDetails3               `xml:"Dtls"`
}

// TaxAmountAndType1 is Amount of money, which has been typed.
type TaxAmountAndType1 struct {
	Tp  *TaxAmountType1Choice              `xml:"Tp"`
	Amt *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
}

// TaxAmountType1Choice is Specifies the amount type, in a free-text form.
type TaxAmountType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// TaxAuthorisation1 is Name of the debtor or the debtor's authorised representative.
type TaxAuthorisation1 struct {
	Titl string `xml:"Titl"`
	Nm   string `xml:"Nm"`
}

// TaxData1 is Record of tax details.
type TaxData1 struct {
	Cdtr            *TaxParty1                         `xml:"Cdtr"`
	Dbtr            *TaxParty2                         `xml:"Dbtr"`
	UltmtDbtr       *TaxParty2                         `xml:"UltmtDbtr"`
	AdmstnZone      string                             `xml:"AdmstnZone"`
	RefNb           string                             `xml:"RefNb"`
	Mtd             string                             `xml:"Mtd"`
	TtlTaxblBaseAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TtlTaxblBaseAmt"`
	TtlTaxAmt       *ActiveOrHistoricCurrencyAndAmount `xml:"TtlTaxAmt"`
	Dt              string                             `xml:"Dt"`
	SeqNb           float64                            `xml:"SeqNb"`
	Rcrd            []*TaxRecord3                      `xml:"Rcrd"`
}

// TaxInformation10 is Record of tax details.
type TaxInformation10 struct {
	Cdtr            *TaxParty1                         `xml:"Cdtr"`
	Dbtr            *TaxParty2                         `xml:"Dbtr"`
	AdmstnZone      string                             `xml:"AdmstnZone"`
	RefNb           string                             `xml:"RefNb"`
	Mtd             string                             `xml:"Mtd"`
	TtlTaxblBaseAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TtlTaxblBaseAmt"`
	TtlTaxAmt       *ActiveOrHistoricCurrencyAndAmount `xml:"TtlTaxAmt"`
	Dt              string                             `xml:"Dt"`
	SeqNb           float64                            `xml:"SeqNb"`
	Rcrd            []*TaxRecord3                      `xml:"Rcrd"`
}

// TaxParty1 is Type of tax payer.
type TaxParty1 struct {
	TaxId  string `xml:"TaxId"`
	RegnId string `xml:"RegnId"`
	TaxTp  string `xml:"TaxTp"`
}

// TaxParty2 is Details of the authorised tax paying party.
type TaxParty2 struct {
	TaxId   string             `xml:"TaxId"`
	RegnId  string             `xml:"RegnId"`
	TaxTp   string             `xml:"TaxTp"`
	Authstn *TaxAuthorisation1 `xml:"Authstn"`
}

// TaxPeriod3 is Range of time between a start date and an end date for which the tax report is provided.
type TaxPeriod3 struct {
	Yr     string       `xml:"Yr"`
	Tp     string       `xml:"Tp"`
	FrToDt *DatePeriod2 `xml:"FrToDt"`
}

// TaxRecord3 is Further details of the tax record.
type TaxRecord3 struct {
	Tp       string      `xml:"Tp"`
	Ctgy     string      `xml:"Ctgy"`
	CtgyDtls string      `xml:"CtgyDtls"`
	DbtrSts  string      `xml:"DbtrSts"`
	CertId   string      `xml:"CertId"`
	FrmsCd   string      `xml:"FrmsCd"`
	Prd      *TaxPeriod3 `xml:"Prd"`
	TaxAmt   *TaxAmount3 `xml:"TaxAmt"`
	AddtlInf string      `xml:"AddtlInf"`
}

// TaxRecordDetails3 is Underlying tax amount related to the specified period.
type TaxRecordDetails3 struct {
	Prd *TaxPeriod3                        `xml:"Prd"`
	Amt *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
}

// TaxRecordPeriod1Code is Tax is related to the second half of the period.
type TaxRecordPeriod1Code string

// TransactionParties10 is Ultimate party to which an amount of money is due.
type TransactionParties10 struct {
	UltmtDbtr         *Party40Choice                                `xml:"UltmtDbtr"`
	Dbtr              *Party40Choice                                `xml:"Dbtr"`
	DbtrAcct          *CashAccount40                                `xml:"DbtrAcct"`
	InitgPty          *Party40Choice                                `xml:"InitgPty"`
	DbtrAgt           *BranchAndFinancialInstitutionIdentification6 `xml:"DbtrAgt"`
	DbtrAgtAcct       *CashAccount40                                `xml:"DbtrAgtAcct"`
	PrvsInstgAgt1     *BranchAndFinancialInstitutionIdentification6 `xml:"PrvsInstgAgt1"`
	PrvsInstgAgt1Acct *CashAccount40                                `xml:"PrvsInstgAgt1Acct"`
	PrvsInstgAgt2     *BranchAndFinancialInstitutionIdentification6 `xml:"PrvsInstgAgt2"`
	PrvsInstgAgt2Acct *CashAccount40                                `xml:"PrvsInstgAgt2Acct"`
	PrvsInstgAgt3     *BranchAndFinancialInstitutionIdentification6 `xml:"PrvsInstgAgt3"`
	PrvsInstgAgt3Acct *CashAccount40                                `xml:"PrvsInstgAgt3Acct"`
	IntrmyAgt1        *BranchAndFinancialInstitutionIdentification6 `xml:"IntrmyAgt1"`
	IntrmyAgt1Acct    *CashAccount40                                `xml:"IntrmyAgt1Acct"`
	IntrmyAgt2        *BranchAndFinancialInstitutionIdentification6 `xml:"IntrmyAgt2"`
	IntrmyAgt2Acct    *CashAccount40                                `xml:"IntrmyAgt2Acct"`
	IntrmyAgt3        *BranchAndFinancialInstitutionIdentification6 `xml:"IntrmyAgt3"`
	IntrmyAgt3Acct    *CashAccount40                                `xml:"IntrmyAgt3Acct"`
	CdtrAgt           *BranchAndFinancialInstitutionIdentification6 `xml:"CdtrAgt"`
	CdtrAgtAcct       *CashAccount40                                `xml:"CdtrAgtAcct"`
	Cdtr              *Party40Choice                                `xml:"Cdtr"`
	CdtrAcct          *CashAccount40                                `xml:"CdtrAcct"`
	UltmtCdtr         *Party40Choice                                `xml:"UltmtCdtr"`
}

// TrueFalseIndicator is A flag indicating a True or False value.
type TrueFalseIndicator bool

// UUIDv4Identifier is Universally Unique IDentifier (UUID) version 4, as described in IETC RFC 4122 "Universally Unique IDentifier (UUID) URN Namespace".
type UUIDv4Identifier string
