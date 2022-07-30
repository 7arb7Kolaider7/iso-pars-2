package schema

import (
	"time"
)

// Document ...
type Document *Document

// AccountIdentification4Choice ...
type AccountIdentification4Choice struct {
	IBAN string                         `xml:"IBAN"`
	Othr *GenericAccountIdentification1 `xml:"Othr"`
}

// AccountSchemeName1Choice ...
type AccountSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ActiveCurrencyAndAmountSimpleType ...
type ActiveCurrencyAndAmountSimpleType float64

// ActiveCurrencyAndAmount ...
type ActiveCurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveCurrencyCode ...
type ActiveCurrencyCode string

// ActiveOrHistoricCurrencyCode ...
type ActiveOrHistoricCurrencyCode string

// AddressType2Code ...
type AddressType2Code string

// BICFIIdentifier ...
type BICFIIdentifier string

// BatchBookingIndicator ...
type BatchBookingIndicator bool

// BranchAndFinancialInstitutionIdentification5 ...
type BranchAndFinancialInstitutionIdentification5 struct {
	FinInstnId *FinancialInstitutionIdentification8 `xml:"FinInstnId"`
	BrnchId    *BranchData2                         `xml:"BrnchId"`
}

// BranchData2 ...
type BranchData2 struct {
	Id      string          `xml:"Id"`
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress6 `xml:"PstlAdr"`
}

// CashAccount24 ...
type CashAccount24 struct {
	Id  *AccountIdentification4Choice `xml:"Id"`
	Tp  *CashAccountType2Choice       `xml:"Tp"`
	Ccy string                        `xml:"Ccy"`
	Nm  string                        `xml:"Nm"`
}

// CashAccountType2Choice ...
type CashAccountType2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CategoryPurpose1Choice ...
type CategoryPurpose1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ClearingChannel2Code ...
type ClearingChannel2Code string

// ClearingSystemIdentification2Choice ...
type ClearingSystemIdentification2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ClearingSystemMemberIdentification2 ...
type ClearingSystemMemberIdentification2 struct {
	ClrSysId *ClearingSystemIdentification2Choice `xml:"ClrSysId"`
	MmbId    string                               `xml:"MmbId"`
}

// CountryCode ...
type CountryCode string

// CreditTransferTransaction9 ...
type CreditTransferTransaction9 struct {
	CdtId             string                                        `xml:"CdtId"`
	BtchBookg         bool                                          `xml:"BtchBookg"`
	PmtTpInf          *PaymentTypeInformation21                     `xml:"PmtTpInf"`
	TtlIntrBkSttlmAmt *ActiveCurrencyAndAmount                      `xml:"TtlIntrBkSttlmAmt"`
	IntrBkSttlmDt     string                                        `xml:"IntrBkSttlmDt"`
	InstgAgt          *BranchAndFinancialInstitutionIdentification5 `xml:"InstgAgt"`
	InstdAgt          *BranchAndFinancialInstitutionIdentification5 `xml:"InstdAgt"`
	IntrmyAgt1        *BranchAndFinancialInstitutionIdentification5 `xml:"IntrmyAgt1"`
	IntrmyAgt1Acct    *CashAccount24                                `xml:"IntrmyAgt1Acct"`
	IntrmyAgt2        *BranchAndFinancialInstitutionIdentification5 `xml:"IntrmyAgt2"`
	IntrmyAgt2Acct    *CashAccount24                                `xml:"IntrmyAgt2Acct"`
	IntrmyAgt3        *BranchAndFinancialInstitutionIdentification5 `xml:"IntrmyAgt3"`
	IntrmyAgt3Acct    *CashAccount24                                `xml:"IntrmyAgt3Acct"`
	CdtrAgt           *BranchAndFinancialInstitutionIdentification5 `xml:"CdtrAgt"`
	CdtrAgtAcct       *CashAccount24                                `xml:"CdtrAgtAcct"`
	Cdtr              *BranchAndFinancialInstitutionIdentification5 `xml:"Cdtr"`
	CdtrAcct          *CashAccount24                                `xml:"CdtrAcct"`
	UltmtCdtr         *BranchAndFinancialInstitutionIdentification5 `xml:"UltmtCdtr"`
	InstrForCdtrAgt   []*InstructionForCreditorAgent2               `xml:"InstrForCdtrAgt"`
	DrctDbtTxInf      []*DirectDebitTransactionInformation15        `xml:"DrctDbtTxInf"`
	SplmtryData       []*SupplementaryData1                         `xml:"SplmtryData"`
}

// DecimalNumber ...
type DecimalNumber float64

// DirectDebitTransactionInformation15 ...
type DirectDebitTransactionInformation15 struct {
	PmtId           *PaymentIdentification3                       `xml:"PmtId"`
	PmtTpInf        *PaymentTypeInformation21                     `xml:"PmtTpInf"`
	IntrBkSttlmAmt  *ActiveCurrencyAndAmount                      `xml:"IntrBkSttlmAmt"`
	IntrBkSttlmDt   string                                        `xml:"IntrBkSttlmDt"`
	SttlmPrty       string                                        `xml:"SttlmPrty"`
	SttlmTmReq      *SettlementTimeRequest2                       `xml:"SttlmTmReq"`
	UltmtDbtr       *BranchAndFinancialInstitutionIdentification5 `xml:"UltmtDbtr"`
	Dbtr            *BranchAndFinancialInstitutionIdentification5 `xml:"Dbtr"`
	DbtrAcct        *CashAccount24                                `xml:"DbtrAcct"`
	DbtrAgt         *BranchAndFinancialInstitutionIdentification5 `xml:"DbtrAgt"`
	DbtrAgtAcct     *CashAccount24                                `xml:"DbtrAgtAcct"`
	InstrForDbtrAgt string                                        `xml:"InstrForDbtrAgt"`
	RmtInf          *RemittanceInformation2                       `xml:"RmtInf"`
}

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalCashAccountType1Code ...
type ExternalCashAccountType1Code string

// ExternalCategoryPurpose1Code ...
type ExternalCategoryPurpose1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalLocalInstrument1Code ...
type ExternalLocalInstrument1Code string

// ExternalServiceLevel1Code ...
type ExternalServiceLevel1Code string

// FinancialIdentificationSchemeName1Choice ...
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// FinancialInstitutionDirectDebitV02 ...
type FinancialInstitutionDirectDebitV02 struct {
	GrpHdr      *GroupHeader63                `xml:"GrpHdr"`
	CdtInstr    []*CreditTransferTransaction9 `xml:"CdtInstr"`
	SplmtryData []*SupplementaryData1         `xml:"SplmtryData"`
}

// FinancialInstitutionIdentification8 ...
type FinancialInstitutionIdentification8 struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	Nm          string                               `xml:"Nm"`
	PstlAdr     *PostalAddress6                      `xml:"PstlAdr"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
}

// GenericAccountIdentification1 ...
type GenericAccountIdentification1 struct {
	Id      string                    `xml:"Id"`
	SchmeNm *AccountSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                    `xml:"Issr"`
}

// GenericFinancialIdentification1 ...
type GenericFinancialIdentification1 struct {
	Id      string                                    `xml:"Id"`
	SchmeNm *FinancialIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                    `xml:"Issr"`
}

// GroupHeader63 ...
type GroupHeader63 struct {
	MsgId    string                                        `xml:"MsgId"`
	CreDtTm  string                                        `xml:"CreDtTm"`
	NbOfTxs  string                                        `xml:"NbOfTxs"`
	CtrlSum  float64                                       `xml:"CtrlSum"`
	InstgAgt *BranchAndFinancialInstitutionIdentification5 `xml:"InstgAgt"`
	InstdAgt *BranchAndFinancialInstitutionIdentification5 `xml:"InstdAgt"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ISOTime ...
type ISOTime time.Time

// Instruction5Code ...
type Instruction5Code string

// InstructionForCreditorAgent2 ...
type InstructionForCreditorAgent2 struct {
	Cd       string `xml:"Cd"`
	InstrInf string `xml:"InstrInf"`
}

// LocalInstrument2Choice ...
type LocalInstrument2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Max140Text ...
type Max140Text string

// Max15NumericText ...
type Max15NumericText string

// Max16Text ...
type Max16Text string

// Max210Text ...
type Max210Text string

// Max34Text ...
type Max34Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Max70Text ...
type Max70Text string

// PaymentIdentification3 ...
type PaymentIdentification3 struct {
	InstrId    string `xml:"InstrId"`
	EndToEndId string `xml:"EndToEndId"`
	TxId       string `xml:"TxId"`
	ClrSysRef  string `xml:"ClrSysRef"`
}

// PaymentTypeInformation21 ...
type PaymentTypeInformation21 struct {
	InstrPrty string                  `xml:"InstrPrty"`
	ClrChanl  string                  `xml:"ClrChanl"`
	SvcLvl    *ServiceLevel8Choice    `xml:"SvcLvl"`
	LclInstrm *LocalInstrument2Choice `xml:"LclInstrm"`
	CtgyPurp  *CategoryPurpose1Choice `xml:"CtgyPurp"`
}

// PostalAddress6 ...
type PostalAddress6 struct {
	AdrTp       string   `xml:"AdrTp"`
	Dept        string   `xml:"Dept"`
	SubDept     string   `xml:"SubDept"`
	StrtNm      string   `xml:"StrtNm"`
	BldgNb      string   `xml:"BldgNb"`
	PstCd       string   `xml:"PstCd"`
	TwnNm       string   `xml:"TwnNm"`
	CtrySubDvsn string   `xml:"CtrySubDvsn"`
	Ctry        string   `xml:"Ctry"`
	AdrLine     []string `xml:"AdrLine"`
}

// Priority2Code ...
type Priority2Code string

// Priority3Code ...
type Priority3Code string

// RemittanceInformation2 ...
type RemittanceInformation2 struct {
	Ustrd []string `xml:"Ustrd"`
}

// ServiceLevel8Choice ...
type ServiceLevel8Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SettlementTimeRequest2 ...
type SettlementTimeRequest2 struct {
	CLSTm  time.Time `xml:"CLSTm"`
	TillTm time.Time `xml:"TillTm"`
	FrTm   time.Time `xml:"FrTm"`
	RjctTm time.Time `xml:"RjctTm"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}
