package schema

// Document ...
type Document *Document

// ActiveCurrencyAndAmountSimpleType ...
type ActiveCurrencyAndAmountSimpleType float64

// ActiveCurrencyAndAmount ...
type ActiveCurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveCurrencyCode ...
type ActiveCurrencyCode string

// Amount2Choice ...
type Amount2Choice struct {
	AmtWthtCcy float64                  `xml:"AmtWthtCcy"`
	AmtWthCcy  *ActiveCurrencyAndAmount `xml:"AmtWthCcy"`
}

// BICFIDec2014Identifier ...
type BICFIDec2014Identifier string

// BackupPaymentV07 ...
type BackupPaymentV07 struct {
	MsgHdr      *MessageHeader1       `xml:"MsgHdr"`
	OrgnlMsgId  *MessageHeader1       `xml:"OrgnlMsgId"`
	InstrInf    *PaymentInstruction13 `xml:"InstrInf"`
	TrfdAmt     *Amount2Choice        `xml:"TrfdAmt"`
	Cdtr        *SystemMember3        `xml:"Cdtr"`
	CdtrAgt     *SystemMember3        `xml:"CdtrAgt"`
	DbtrAgt     *SystemMember3        `xml:"DbtrAgt"`
	SplmtryData []*SupplementaryData1 `xml:"SplmtryData"`
}

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

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalMarketInfrastructure1Code ...
type ExternalMarketInfrastructure1Code string

// FinancialIdentificationSchemeName1Choice ...
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// GenericFinancialIdentification1 ...
type GenericFinancialIdentification1 struct {
	Id      string                                    `xml:"Id"`
	SchmeNm *FinancialIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                    `xml:"Issr"`
}

// ISODateTime ...
type ISODateTime string

// ImpliedCurrencyAndAmount ...
type ImpliedCurrencyAndAmount float64

// MarketInfrastructureIdentification1Choice ...
type MarketInfrastructureIdentification1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// MemberIdentification3Choice ...
type MemberIdentification3Choice struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
}

// MessageHeader1 ...
type MessageHeader1 struct {
	MsgId   string `xml:"MsgId"`
	CreDtTm string `xml:"CreDtTm"`
}

// PaymentInstruction13 ...
type PaymentInstruction13 struct {
	ReqdExctnDtTm string              `xml:"ReqdExctnDtTm"`
	PmtTp         *PaymentType4Choice `xml:"PmtTp"`
}

// PaymentType3Code ...
type PaymentType3Code string

// PaymentType4Choice ...
type PaymentType4Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// SystemIdentification2Choice ...
type SystemIdentification2Choice struct {
	MktInfrstrctrId *MarketInfrastructureIdentification1Choice `xml:"MktInfrstrctrId"`
	Ctry            string                                     `xml:"Ctry"`
}

// SystemMember3 ...
type SystemMember3 struct {
	SysId *SystemIdentification2Choice `xml:"SysId"`
	MmbId *MemberIdentification3Choice `xml:"MmbId"`
}
