package schema

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

// ActiveOrHistoricCurrencyCode ...
type ActiveOrHistoricCurrencyCode string

// BICFIDec2014Identifier ...
type BICFIDec2014Identifier string

// CashAccount38 ...
type CashAccount38 struct {
	Id   *AccountIdentification4Choice `xml:"Id"`
	Tp   *CashAccountType2Choice       `xml:"Tp"`
	Ccy  string                        `xml:"Ccy"`
	Nm   string                        `xml:"Nm"`
	Prxy *ProxyAccountIdentification1  `xml:"Prxy"`
}

// CashAccountType2Choice ...
type CashAccountType2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
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

// CommunicationAddress10 ...
type CommunicationAddress10 struct {
	PstlAdr  *LongPostalAddress1Choice `xml:"PstlAdr"`
	PhneNb   string                    `xml:"PhneNb"`
	FaxNb    string                    `xml:"FaxNb"`
	EmailAdr string                    `xml:"EmailAdr"`
}

// ContactIdentificationAndAddress2 ...
type ContactIdentificationAndAddress2 struct {
	Nm     string                  `xml:"Nm"`
	Role   *PaymentRole1Choice     `xml:"Role"`
	ComAdr *CommunicationAddress10 `xml:"ComAdr"`
}

// CountryCode ...
type CountryCode string

// ErrorHandling1Choice ...
type ErrorHandling1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ErrorHandling1Code ...
type ErrorHandling1Code string

// ErrorHandling3 ...
type ErrorHandling3 struct {
	Err  *ErrorHandling1Choice `xml:"Err"`
	Desc string                `xml:"Desc"`
}

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalCashAccountType1Code ...
type ExternalCashAccountType1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalEnquiryRequestType1Code ...
type ExternalEnquiryRequestType1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalPaymentControlRequestType1Code ...
type ExternalPaymentControlRequestType1Code string

// ExternalPaymentRole1Code ...
type ExternalPaymentRole1Code string

// ExternalProxyAccountType1Code ...
type ExternalProxyAccountType1Code string

// ExternalSystemMemberType1Code ...
type ExternalSystemMemberType1Code string

// FinancialIdentificationSchemeName1Choice ...
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
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

// GenericIdentification1 ...
type GenericIdentification1 struct {
	Id      string `xml:"Id"`
	SchmeNm string `xml:"SchmeNm"`
	Issr    string `xml:"Issr"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

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

// Max2048Text ...
type Max2048Text string

// Max34Text ...
type Max34Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Max4AlphaNumericText ...
type Max4AlphaNumericText string

// Max70Text ...
type Max70Text string

// Member5 ...
type Member5 struct {
	Nm      string                              `xml:"Nm"`
	RtrAdr  []*MemberIdentification3Choice      `xml:"RtrAdr"`
	Acct    []*CashAccount38                    `xml:"Acct"`
	Tp      *SystemMemberType1Choice            `xml:"Tp"`
	Sts     *SystemMemberStatus1Choice          `xml:"Sts"`
	CtctRef []*ContactIdentificationAndAddress2 `xml:"CtctRef"`
	ComAdr  *CommunicationAddress10             `xml:"ComAdr"`
}

// MemberIdentification3Choice ...
type MemberIdentification3Choice struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
}

// MemberReport5 ...
type MemberReport5 struct {
	MmbId    *MemberIdentification3Choice `xml:"MmbId"`
	MmbOrErr *MemberReportOrError6Choice  `xml:"MmbOrErr"`
}

// MemberReportOrError5Choice ...
type MemberReportOrError5Choice struct {
	Rpt     []*MemberReport5  `xml:"Rpt"`
	OprlErr []*ErrorHandling3 `xml:"OprlErr"`
}

// MemberReportOrError6Choice ...
type MemberReportOrError6Choice struct {
	Mmb    *Member5        `xml:"Mmb"`
	BizErr *ErrorHandling3 `xml:"BizErr"`
}

// MemberStatus1Code ...
type MemberStatus1Code string

// MessageHeader7 ...
type MessageHeader7 struct {
	MsgId       string                  `xml:"MsgId"`
	CreDtTm     string                  `xml:"CreDtTm"`
	ReqTp       *RequestType4Choice     `xml:"ReqTp"`
	OrgnlBizQry *OriginalBusinessQuery1 `xml:"OrgnlBizQry"`
	QryNm       string                  `xml:"QryNm"`
}

// OriginalBusinessQuery1 ...
type OriginalBusinessQuery1 struct {
	MsgId   string `xml:"MsgId"`
	MsgNmId string `xml:"MsgNmId"`
	CreDtTm string `xml:"CreDtTm"`
}

// PaymentRole1Choice ...
type PaymentRole1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// PhoneNumber ...
type PhoneNumber string

// ProxyAccountIdentification1 ...
type ProxyAccountIdentification1 struct {
	Tp *ProxyAccountType1Choice `xml:"Tp"`
	Id string                   `xml:"Id"`
}

// ProxyAccountType1Choice ...
type ProxyAccountType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// RequestType4Choice ...
type RequestType4Choice struct {
	PmtCtrl string                  `xml:"PmtCtrl"`
	Enqry   string                  `xml:"Enqry"`
	Prtry   *GenericIdentification1 `xml:"Prtry"`
}

// ReturnMemberV04 ...
type ReturnMemberV04 struct {
	MsgHdr      *MessageHeader7             `xml:"MsgHdr"`
	RptOrErr    *MemberReportOrError5Choice `xml:"RptOrErr"`
	SplmtryData []*SupplementaryData1       `xml:"SplmtryData"`
}

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

// SystemMemberStatus1Choice ...
type SystemMemberStatus1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SystemMemberType1Choice ...
type SystemMemberType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}
