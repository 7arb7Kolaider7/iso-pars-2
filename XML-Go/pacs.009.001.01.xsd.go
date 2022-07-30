package schema

import (
	"encoding/xml"
	"time"
)

// Document ...
type Document *Document

// AccountIdentification3Choice ...
type AccountIdentification3Choice struct {
	IBAN      string                            `xml:"IBAN"`
	BBAN      string                            `xml:"BBAN"`
	UPIC      string                            `xml:"UPIC"`
	PrtryAcct *SimpleIdentificationInformation2 `xml:"PrtryAcct"`
}

// AddressType2Code ...
type AddressType2Code string

// BBANIdentifier ...
type BBANIdentifier string

// BICIdentifier ...
type BICIdentifier string

// BatchBookingIndicator ...
type BatchBookingIndicator bool

// BranchAndFinancialInstitutionIdentification3 ...
type BranchAndFinancialInstitutionIdentification3 struct {
	FinInstnId *FinancialInstitutionIdentification5Choice `xml:"FinInstnId"`
	BrnchId    *BranchData                                `xml:"BrnchId"`
}

// BranchData ...
type BranchData struct {
	Id      string          `xml:"Id"`
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress1 `xml:"PstlAdr"`
}

// CashAccount7 ...
type CashAccount7 struct {
	Id  *AccountIdentification3Choice `xml:"Id"`
	Tp  *CashAccountType2             `xml:"Tp"`
	Ccy string                        `xml:"Ccy"`
	Nm  string                        `xml:"Nm"`
}

// CashAccountType2 ...
type CashAccountType2 struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CashAccountType4Code ...
type CashAccountType4Code string

// CashClearingSystem3Code ...
type CashClearingSystem3Code string

// ClearingChannel2Code ...
type ClearingChannel2Code string

// ClearingSystemIdentification1Choice ...
type ClearingSystemIdentification1Choice struct {
	ClrSysId string `xml:"ClrSysId"`
	Prtry    string `xml:"Prtry"`
}

// ClearingSystemMemberIdentification3Choice ...
type ClearingSystemMemberIdentification3Choice struct {
	Id    string `xml:"Id"`
	Prtry string `xml:"Prtry"`
}

// CountryCode ...
type CountryCode string

// CreditTransferTransactionInformation3 ...
type CreditTransferTransactionInformation3 struct {
	PmtId            *PaymentIdentification2                       `xml:"PmtId"`
	PmtTpInf         *PaymentTypeInformation5                      `xml:"PmtTpInf"`
	IntrBkSttlmAmt   *CurrencyAndAmount                            `xml:"IntrBkSttlmAmt"`
	IntrBkSttlmDt    string                                        `xml:"IntrBkSttlmDt"`
	SttlmTmIndctn    *SettlementDateTimeIndication1                `xml:"SttlmTmIndctn"`
	SttlmTmReq       *SettlementTimeRequest1                       `xml:"SttlmTmReq"`
	PrvsInstgAgt     *BranchAndFinancialInstitutionIdentification3 `xml:"PrvsInstgAgt"`
	PrvsInstgAgtAcct *CashAccount7                                 `xml:"PrvsInstgAgtAcct"`
	InstgAgt         *BranchAndFinancialInstitutionIdentification3 `xml:"InstgAgt"`
	InstdAgt         *BranchAndFinancialInstitutionIdentification3 `xml:"InstdAgt"`
	IntrmyAgt1       *BranchAndFinancialInstitutionIdentification3 `xml:"IntrmyAgt1"`
	IntrmyAgt1Acct   *CashAccount7                                 `xml:"IntrmyAgt1Acct"`
	IntrmyAgt2       *BranchAndFinancialInstitutionIdentification3 `xml:"IntrmyAgt2"`
	IntrmyAgt2Acct   *CashAccount7                                 `xml:"IntrmyAgt2Acct"`
	IntrmyAgt3       *BranchAndFinancialInstitutionIdentification3 `xml:"IntrmyAgt3"`
	IntrmyAgt3Acct   *CashAccount7                                 `xml:"IntrmyAgt3Acct"`
	UltmtDbtr        *BranchAndFinancialInstitutionIdentification3 `xml:"UltmtDbtr"`
	Dbtr             *BranchAndFinancialInstitutionIdentification3 `xml:"Dbtr"`
	DbtrAcct         *CashAccount7                                 `xml:"DbtrAcct"`
	DbtrAgt          *BranchAndFinancialInstitutionIdentification3 `xml:"DbtrAgt"`
	DbtrAgtAcct      *CashAccount7                                 `xml:"DbtrAgtAcct"`
	CdtrAgt          *BranchAndFinancialInstitutionIdentification3 `xml:"CdtrAgt"`
	CdtrAgtAcct      *CashAccount7                                 `xml:"CdtrAgtAcct"`
	Cdtr             *BranchAndFinancialInstitutionIdentification3 `xml:"Cdtr"`
	CdtrAcct         *CashAccount7                                 `xml:"CdtrAcct"`
	UltmtCdtr        *BranchAndFinancialInstitutionIdentification3 `xml:"UltmtCdtr"`
	InstrForCdtrAgt  []*InstructionForCreditorAgent2               `xml:"InstrForCdtrAgt"`
	InstrForNxtAgt   []*InstructionForNextAgent1                   `xml:"InstrForNxtAgt"`
	RmtInf           *RemittanceInformation2                       `xml:"RmtInf"`
}

// CurrencyAndAmountSimpleType ...
type CurrencyAndAmountSimpleType float64

// CurrencyAndAmount ...
type CurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// CurrencyCode ...
type CurrencyCode string

// DecimalNumber ...
type DecimalNumber float64

// ExternalClearingSystemMemberCode ...
type ExternalClearingSystemMemberCode string

// FinancialInstitutionIdentification3 ...
type FinancialInstitutionIdentification3 struct {
	BIC         string                                     `xml:"BIC"`
	ClrSysMmbId *ClearingSystemMemberIdentification3Choice `xml:"ClrSysMmbId"`
	Nm          string                                     `xml:"Nm"`
	PstlAdr     *PostalAddress1                            `xml:"PstlAdr"`
	PrtryId     *GenericIdentification3                    `xml:"PrtryId"`
}

// FinancialInstitutionIdentification5Choice ...
type FinancialInstitutionIdentification5Choice struct {
	BIC         string                                     `xml:"BIC"`
	ClrSysMmbId *ClearingSystemMemberIdentification3Choice `xml:"ClrSysMmbId"`
	NmAndAdr    *NameAndAddress7                           `xml:"NmAndAdr"`
	PrtryId     *GenericIdentification3                    `xml:"PrtryId"`
	CmbndId     *FinancialInstitutionIdentification3       `xml:"CmbndId"`
}

// GenericIdentification3 ...
type GenericIdentification3 struct {
	Id   string `xml:"Id"`
	Issr string `xml:"Issr"`
}

// GroupHeader4 ...
type GroupHeader4 struct {
	MsgId             string                                        `xml:"MsgId"`
	CreDtTm           string                                        `xml:"CreDtTm"`
	BtchBookg         bool                                          `xml:"BtchBookg"`
	NbOfTxs           string                                        `xml:"NbOfTxs"`
	CtrlSum           float64                                       `xml:"CtrlSum"`
	TtlIntrBkSttlmAmt *CurrencyAndAmount                            `xml:"TtlIntrBkSttlmAmt"`
	IntrBkSttlmDt     string                                        `xml:"IntrBkSttlmDt"`
	SttlmInf          *SettlementInformation1                       `xml:"SttlmInf"`
	PmtTpInf          *PaymentTypeInformation5                      `xml:"PmtTpInf"`
	InstgAgt          *BranchAndFinancialInstitutionIdentification3 `xml:"InstgAgt"`
	InstdAgt          *BranchAndFinancialInstitutionIdentification3 `xml:"InstdAgt"`
}

// IBANIdentifier ...
type IBANIdentifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ISOTime ...
type ISOTime time.Time

// Instruction4Code ...
type Instruction4Code string

// Instruction5Code ...
type Instruction5Code string

// InstructionForCreditorAgent2 ...
type InstructionForCreditorAgent2 struct {
	Cd       string `xml:"Cd"`
	InstrInf string `xml:"InstrInf"`
}

// InstructionForNextAgent1 ...
type InstructionForNextAgent1 struct {
	Cd       string `xml:"Cd"`
	InstrInf string `xml:"InstrInf"`
}

// Max140Text ...
type Max140Text string

// Max15NumericText ...
type Max15NumericText string

// Max16Text ...
type Max16Text string

// Max34Text ...
type Max34Text string

// Max35Text ...
type Max35Text string

// Max70Text ...
type Max70Text string

// NameAndAddress7 ...
type NameAndAddress7 struct {
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress1 `xml:"PstlAdr"`
}

// PaymentIdentification2 ...
type PaymentIdentification2 struct {
	InstrId    string `xml:"InstrId"`
	EndToEndId string `xml:"EndToEndId"`
	TxId       string `xml:"TxId"`
}

// PaymentTypeInformation5 ...
type PaymentTypeInformation5 struct {
	InstrPrty string                       `xml:"InstrPrty"`
	SvcLvl    *RestrictedProprietaryChoice `xml:"SvcLvl"`
	ClrChanl  string                       `xml:"ClrChanl"`
	LclInstrm *RestrictedProprietaryChoice `xml:"LclInstrm"`
}

// PostalAddress1 ...
type PostalAddress1 struct {
	AdrTp       string   `xml:"AdrTp"`
	AdrLine     []string `xml:"AdrLine"`
	StrtNm      string   `xml:"StrtNm"`
	BldgNb      string   `xml:"BldgNb"`
	PstCd       string   `xml:"PstCd"`
	TwnNm       string   `xml:"TwnNm"`
	CtrySubDvsn string   `xml:"CtrySubDvsn"`
	Ctry        string   `xml:"Ctry"`
}

// Priority2Code ...
type Priority2Code string

// RemittanceInformation2 ...
type RemittanceInformation2 struct {
	Ustrd []string `xml:"Ustrd"`
}

// RestrictedProprietaryChoice ...
type RestrictedProprietaryChoice struct {
	Prtry string `xml:"Prtry"`
}

// SettlementDateTimeIndication1 ...
type SettlementDateTimeIndication1 struct {
	DbtDtTm string `xml:"DbtDtTm"`
	CdtDtTm string `xml:"CdtDtTm"`
}

// SettlementInformation1 ...
type SettlementInformation1 struct {
	SttlmMtd             string                                        `xml:"SttlmMtd"`
	SttlmAcct            *CashAccount7                                 `xml:"SttlmAcct"`
	ClrSys               *ClearingSystemIdentification1Choice          `xml:"ClrSys"`
	InstgRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification3 `xml:"InstgRmbrsmntAgt"`
	InstgRmbrsmntAgtAcct *CashAccount7                                 `xml:"InstgRmbrsmntAgtAcct"`
	InstdRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification3 `xml:"InstdRmbrsmntAgt"`
	InstdRmbrsmntAgtAcct *CashAccount7                                 `xml:"InstdRmbrsmntAgtAcct"`
	ThrdRmbrsmntAgt      *BranchAndFinancialInstitutionIdentification3 `xml:"ThrdRmbrsmntAgt"`
	ThrdRmbrsmntAgtAcct  *CashAccount7                                 `xml:"ThrdRmbrsmntAgtAcct"`
}

// SettlementMethod1Code ...
type SettlementMethod1Code string

// SettlementTimeRequest1 ...
type SettlementTimeRequest1 struct {
	CLSTm time.Time `xml:"CLSTm"`
}

// SimpleIdentificationInformation2 ...
type SimpleIdentificationInformation2 struct {
	Id string `xml:"Id"`
}

// UPICIdentifier ...
type UPICIdentifier string

// Pacs00900101 ...
type Pacs00900101 struct {
	XMLName     xml.Name                                 `xml:"pacs.009.001.01"`
	GrpHdr      *GroupHeader4                            `xml:"GrpHdr"`
	CdtTrfTxInf []*CreditTransferTransactionInformation3 `xml:"CdtTrfTxInf"`
}
