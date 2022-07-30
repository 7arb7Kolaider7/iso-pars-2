package schema

// Document ...
type Document *Document

// AddressType2Code ...
type AddressType2Code string

// AddressType3Choice ...
type AddressType3Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// BICFIDec2014Identifier ...
type BICFIDec2014Identifier string

// BranchAndFinancialInstitutionIdentification6 ...
type BranchAndFinancialInstitutionIdentification6 struct {
	FinInstnId *FinancialInstitutionIdentification18 `xml:"FinInstnId"`
	BrnchId    *BranchData3                          `xml:"BrnchId"`
}

// BranchData3 ...
type BranchData3 struct {
	Id      string           `xml:"Id"`
	LEI     string           `xml:"LEI"`
	Nm      string           `xml:"Nm"`
	PstlAdr *PostalAddress24 `xml:"PstlAdr"`
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

// EntryTypeIdentifier ...
type EntryTypeIdentifier string

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalEnquiryRequestType1Code ...
type ExternalEnquiryRequestType1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalPaymentControlRequestType1Code ...
type ExternalPaymentControlRequestType1Code string

// FinancialIdentificationSchemeName1Choice ...
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// FinancialInstitutionIdentification18 ...
type FinancialInstitutionIdentification18 struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	LEI         string                               `xml:"LEI"`
	Nm          string                               `xml:"Nm"`
	PstlAdr     *PostalAddress24                     `xml:"PstlAdr"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
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

// GenericIdentification30 ...
type GenericIdentification30 struct {
	Id      string `xml:"Id"`
	Issr    string `xml:"Issr"`
	SchmeNm string `xml:"SchmeNm"`
}

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ImpliedCurrencyAndAmount ...
type ImpliedCurrencyAndAmount float64

// LEIIdentifier ...
type LEIIdentifier string

// LongPaymentIdentification2 ...
type LongPaymentIdentification2 struct {
	TxId           string                                        `xml:"TxId"`
	UETR           string                                        `xml:"UETR"`
	IntrBkSttlmAmt float64                                       `xml:"IntrBkSttlmAmt"`
	IntrBkSttlmDt  string                                        `xml:"IntrBkSttlmDt"`
	PmtMtd         *PaymentOrigin1Choice                         `xml:"PmtMtd"`
	InstgAgt       *BranchAndFinancialInstitutionIdentification6 `xml:"InstgAgt"`
	InstdAgt       *BranchAndFinancialInstitutionIdentification6 `xml:"InstdAgt"`
	NtryTp         string                                        `xml:"NtryTp"`
	EndToEndId     string                                        `xml:"EndToEndId"`
}

// Max140Text ...
type Max140Text string

// Max16Text ...
type Max16Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Max3NumericText ...
type Max3NumericText string

// Max4AlphaNumericText ...
type Max4AlphaNumericText string

// Max70Text ...
type Max70Text string

// MessageHeader9 ...
type MessageHeader9 struct {
	MsgId   string              `xml:"MsgId"`
	CreDtTm string              `xml:"CreDtTm"`
	ReqTp   *RequestType4Choice `xml:"ReqTp"`
}

// OriginalMessageAndIssuer1 ...
type OriginalMessageAndIssuer1 struct {
	MsgId   string `xml:"MsgId"`
	MsgNmId string `xml:"MsgNmId"`
	OrgtrNm string `xml:"OrgtrNm"`
}

// PaymentIdentification6Choice ...
type PaymentIdentification6Choice struct {
	TxId      string                           `xml:"TxId"`
	QId       *QueueTransactionIdentification1 `xml:"QId"`
	LngBizId  *LongPaymentIdentification2      `xml:"LngBizId"`
	ShrtBizId *ShortPaymentIdentification2     `xml:"ShrtBizId"`
	PrtryId   string                           `xml:"PrtryId"`
}

// PaymentInstrument1Code ...
type PaymentInstrument1Code string

// PaymentOrigin1Choice ...
type PaymentOrigin1Choice struct {
	FINMT    string `xml:"FINMT"`
	XMLMsgNm string `xml:"XMLMsgNm"`
	Prtry    string `xml:"Prtry"`
	Instrm   string `xml:"Instrm"`
}

// PostalAddress24 ...
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

// QueueTransactionIdentification1 ...
type QueueTransactionIdentification1 struct {
	QId    string `xml:"QId"`
	PosInQ string `xml:"PosInQ"`
}

// Receipt3 ...
type Receipt3 struct {
	OrgnlMsgId *OriginalMessageAndIssuer1    `xml:"OrgnlMsgId"`
	OrgnlPmtId *PaymentIdentification6Choice `xml:"OrgnlPmtId"`
	ReqHdlg    []*RequestHandling1           `xml:"ReqHdlg"`
}

// ReceiptV05 ...
type ReceiptV05 struct {
	MsgHdr      *MessageHeader9       `xml:"MsgHdr"`
	RctDtls     []*Receipt3           `xml:"RctDtls"`
	SplmtryData []*SupplementaryData1 `xml:"SplmtryData"`
}

// RequestHandling1 ...
type RequestHandling1 struct {
	StsCd string `xml:"StsCd"`
	Desc  string `xml:"Desc"`
}

// RequestType4Choice ...
type RequestType4Choice struct {
	PmtCtrl string                  `xml:"PmtCtrl"`
	Enqry   string                  `xml:"Enqry"`
	Prtry   *GenericIdentification1 `xml:"Prtry"`
}

// ShortPaymentIdentification2 ...
type ShortPaymentIdentification2 struct {
	TxId          string                                        `xml:"TxId"`
	IntrBkSttlmDt string                                        `xml:"IntrBkSttlmDt"`
	InstgAgt      *BranchAndFinancialInstitutionIdentification6 `xml:"InstgAgt"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// UUIDv4Identifier ...
type UUIDv4Identifier string
