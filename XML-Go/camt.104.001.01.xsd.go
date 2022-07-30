package schema

// Document ...
type Document *Document

// BICFIDec2014Identifier ...
type BICFIDec2014Identifier string

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

// CommunicationAddress8 ...
type CommunicationAddress8 struct {
	PstlAdr  *LongPostalAddress1Choice `xml:"PstlAdr"`
	PhneNb   string                    `xml:"PhneNb"`
	FaxNb    string                    `xml:"FaxNb"`
	EmailAdr string                    `xml:"EmailAdr"`
}

// ContactIdentificationAndAddress1 ...
type ContactIdentificationAndAddress1 struct {
	Nm     string                 `xml:"Nm"`
	Role   string                 `xml:"Role"`
	ComAdr *CommunicationAddress8 `xml:"ComAdr"`
}

// CountryCode ...
type CountryCode string

// CreateMemberV01 ...
type CreateMemberV01 struct {
	MsgHdr      *MessageHeader1              `xml:"MsgHdr"`
	MmbId       *MemberIdentification3Choice `xml:"MmbId"`
	ValSet      *Member6                     `xml:"ValSet"`
	SplmtryData []*SupplementaryData1        `xml:"SplmtryData"`
}

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

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

// LongPostalAddress1Choice ...
type LongPostalAddress1Choice struct {
	Ustrd string                        `xml:"Ustrd"`
	Strd  *StructuredLongPostalAddress1 `xml:"Strd"`
}

// Max140Text ...
type Max140Text string

// Max16Text ...
type Max16Text string

// Max256Text ...
type Max256Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Member6 ...
type Member6 struct {
	MmbRtrAdr []*MemberIdentification3Choice      `xml:"MmbRtrAdr"`
	CtctRef   []*ContactIdentificationAndAddress1 `xml:"CtctRef"`
	ComAdr    *CommunicationAddress8              `xml:"ComAdr"`
}

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

// PaymentRole1Code ...
type PaymentRole1Code string

// PhoneNumber ...
type PhoneNumber string

// StructuredLongPostalAddress1 ...
type StructuredLongPostalAddress1 struct {
	BldgNm     string `xml:"BldgNm"`
	StrtNm     string `xml:"StrtNm"`
	StrtBldgId string `xml:"StrtBldgId"`
	Flr        string `xml:"Flr"`
	TwnNm      string `xml:"TwnNm"`
	DstrctNm   string `xml:"DstrctNm"`
	RgnId      string `xml:"RgnId"`
	Stat       string `xml:"Stat"`
	CtyId      string `xml:"CtyId"`
	Ctry       string `xml:"Ctry"`
	PstCdId    string `xml:"PstCdId"`
	POB        string `xml:"POB"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}
