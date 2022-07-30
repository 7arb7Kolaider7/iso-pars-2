package schema

import (
	"time"
)

// Document ...
type Document *Document

// ActiveCurrencyCode ...
type ActiveCurrencyCode string

// BusinessDay8 ...
type BusinessDay8 struct {
	SysId       []*SystemIdentification2Choice    `xml:"SysId"`
	BizDayOrErr *BusinessDayReportOrError10Choice `xml:"BizDayOrErr"`
}

// BusinessDay9 ...
type BusinessDay9 struct {
	SysDt        *DateAndDateTime2Choice         `xml:"SysDt"`
	SysSts       *SystemStatus3                  `xml:"SysSts"`
	SysInfPerCcy []*SystemAvailabilityAndEvents3 `xml:"SysInfPerCcy"`
}

// BusinessDayReportOrError10Choice ...
type BusinessDayReportOrError10Choice struct {
	BizDayInf *BusinessDay9     `xml:"BizDayInf"`
	BizErr    []*ErrorHandling5 `xml:"BizErr"`
}

// BusinessDayReportOrError9Choice ...
type BusinessDayReportOrError9Choice struct {
	BizRpt  []*BusinessDay8   `xml:"BizRpt"`
	OprlErr []*ErrorHandling5 `xml:"OprlErr"`
}

// ClosureReason2Choice ...
type ClosureReason2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CountryCode ...
type CountryCode string

// DateAndDateTime2Choice ...
type DateAndDateTime2Choice struct {
	Dt   string `xml:"Dt"`
	DtTm string `xml:"DtTm"`
}

// DateTimePeriod1 ...
type DateTimePeriod1 struct {
	FrDtTm string `xml:"FrDtTm"`
	ToDtTm string `xml:"ToDtTm"`
}

// DateTimePeriod1Choice ...
type DateTimePeriod1Choice struct {
	FrDtTm string           `xml:"FrDtTm"`
	ToDtTm string           `xml:"ToDtTm"`
	DtTmRg *DateTimePeriod1 `xml:"DtTmRg"`
}

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

// ExternalMarketInfrastructure1Code ...
type ExternalMarketInfrastructure1Code string

// ExternalPaymentControlRequestType1Code ...
type ExternalPaymentControlRequestType1Code string

// ExternalSystemErrorHandling1Code ...
type ExternalSystemErrorHandling1Code string

// ExternalSystemEventType1Code ...
type ExternalSystemEventType1Code string

// GenericIdentification1 ...
type GenericIdentification1 struct {
	Id      string `xml:"Id"`
	SchmeNm string `xml:"SchmeNm"`
	Issr    string `xml:"Issr"`
}

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ISOTime ...
type ISOTime time.Time

// MarketInfrastructureIdentification1Choice ...
type MarketInfrastructureIdentification1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
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

// RequestType4Choice ...
type RequestType4Choice struct {
	PmtCtrl string                  `xml:"PmtCtrl"`
	Enqry   string                  `xml:"Enqry"`
	Prtry   *GenericIdentification1 `xml:"Prtry"`
}

// ReturnBusinessDayInformationV07 ...
type ReturnBusinessDayInformationV07 struct {
	MsgHdr      *MessageHeader7                  `xml:"MsgHdr"`
	RptOrErr    *BusinessDayReportOrError9Choice `xml:"RptOrErr"`
	SplmtryData []*SupplementaryData1            `xml:"SplmtryData"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// SystemAvailabilityAndEvents3 ...
type SystemAvailabilityAndEvents3 struct {
	SysCcy  string            `xml:"SysCcy"`
	SsnPrd  *TimePeriod1      `xml:"SsnPrd"`
	Evt     []*SystemEvent3   `xml:"Evt"`
	ClsrInf []*SystemClosure2 `xml:"ClsrInf"`
}

// SystemClosure2 ...
type SystemClosure2 struct {
	Prd *DateTimePeriod1Choice `xml:"Prd"`
	Rsn *ClosureReason2Choice  `xml:"Rsn"`
}

// SystemClosureReason1Code ...
type SystemClosureReason1Code string

// SystemEvent3 ...
type SystemEvent3 struct {
	Tp       *SystemEventType4Choice `xml:"Tp"`
	SchdldTm string                  `xml:"SchdldTm"`
	FctvTm   string                  `xml:"FctvTm"`
	StartTm  string                  `xml:"StartTm"`
	EndTm    string                  `xml:"EndTm"`
}

// SystemEventType4Choice ...
type SystemEventType4Choice struct {
	Cd    string                  `xml:"Cd"`
	Prtry *GenericIdentification1 `xml:"Prtry"`
}

// SystemIdentification2Choice ...
type SystemIdentification2Choice struct {
	MktInfrstrctrId *MarketInfrastructureIdentification1Choice `xml:"MktInfrstrctrId"`
	Ctry            string                                     `xml:"Ctry"`
}

// SystemStatus2Choice ...
type SystemStatus2Choice struct {
	Cd    string                  `xml:"Cd"`
	Prtry *GenericIdentification1 `xml:"Prtry"`
}

// SystemStatus2Code ...
type SystemStatus2Code string

// SystemStatus3 ...
type SystemStatus3 struct {
	Sts     *SystemStatus2Choice   `xml:"Sts"`
	VldtyTm *DateTimePeriod1Choice `xml:"VldtyTm"`
}

// TimePeriod1 ...
type TimePeriod1 struct {
	FrTm time.Time `xml:"FrTm"`
	ToTm time.Time `xml:"ToTm"`
}
