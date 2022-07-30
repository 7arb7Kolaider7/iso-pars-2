package schema

// Document ...
type Document *Document

// ErrorHandling3Choice ...
type ErrorHandling3Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ErrorHandling5 ...
type ErrorHandling5 struct {
	Err  *ErrorHandling3Choice `xml:"Err"`
	Desc string                `xml:"Desc"`
}

// ExternalEnquiryRequestType1Code ...
type ExternalEnquiryRequestType1Code string

// ExternalPaymentControlRequestType1Code ...
type ExternalPaymentControlRequestType1Code string

// ExternalSystemErrorHandling1Code ...
type ExternalSystemErrorHandling1Code string

// GeneralBusinessInformation1 ...
type GeneralBusinessInformation1 struct {
	Qlfr     *InformationQualifierType1 `xml:"Qlfr"`
	Sbjt     string                     `xml:"Sbjt"`
	SbjtDtls string                     `xml:"SbjtDtls"`
}

// GeneralBusinessOrError7Choice ...
type GeneralBusinessOrError7Choice struct {
	OprlErr []*ErrorHandling5         `xml:"OprlErr"`
	BizRpt  []*GeneralBusinessReport6 `xml:"BizRpt"`
}

// GeneralBusinessOrError8Choice ...
type GeneralBusinessOrError8Choice struct {
	BizErr []*ErrorHandling5            `xml:"BizErr"`
	GnlBiz *GeneralBusinessInformation1 `xml:"GnlBiz"`
}

// GeneralBusinessReport6 ...
type GeneralBusinessReport6 struct {
	BizInfRef   string                         `xml:"BizInfRef"`
	GnlBizOrErr *GeneralBusinessOrError8Choice `xml:"GnlBizOrErr"`
}

// GenericIdentification1 ...
type GenericIdentification1 struct {
	Id      string `xml:"Id"`
	SchmeNm string `xml:"SchmeNm"`
	Issr    string `xml:"Issr"`
}

// ISODateTime ...
type ISODateTime string

// InformationQualifierType1 ...
type InformationQualifierType1 struct {
	IsFrmtd bool   `xml:"IsFrmtd"`
	Prty    string `xml:"Prty"`
}

// Max140Text ...
type Max140Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

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

// Priority1Code ...
type Priority1Code string

// RequestType4Choice ...
type RequestType4Choice struct {
	PmtCtrl string                  `xml:"PmtCtrl"`
	Enqry   string                  `xml:"Enqry"`
	Prtry   *GenericIdentification1 `xml:"Prtry"`
}

// ReturnGeneralBusinessInformationV06 ...
type ReturnGeneralBusinessInformationV06 struct {
	MsgHdr      *MessageHeader7                `xml:"MsgHdr"`
	RptOrErr    *GeneralBusinessOrError7Choice `xml:"RptOrErr"`
	SplmtryData []*SupplementaryData1          `xml:"SplmtryData"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// YesNoIndicator ...
type YesNoIndicator bool
