package schema

// Document ...
type Document *Document

// ActiveCurrencyCode ...
type ActiveCurrencyCode string

// BusinessDayCriteria2 ...
type BusinessDayCriteria2 struct {
	NewQryNm string                        `xml:"NewQryNm"`
	SchCrit  []*BusinessDaySearchCriteria2 `xml:"SchCrit"`
	RtrCrit  *BusinessDayReturnCriteria2   `xml:"RtrCrit"`
}

// BusinessDayCriteria3Choice ...
type BusinessDayCriteria3Choice struct {
	QryNm   string                `xml:"QryNm"`
	NewCrit *BusinessDayCriteria2 `xml:"NewCrit"`
}

// BusinessDayQuery2 ...
type BusinessDayQuery2 struct {
	QryTp string                      `xml:"QryTp"`
	Crit  *BusinessDayCriteria3Choice `xml:"Crit"`
}

// BusinessDayReturnCriteria2 ...
type BusinessDayReturnCriteria2 struct {
	SysDtInd   bool `xml:"SysDtInd"`
	SysStsInd  bool `xml:"SysStsInd"`
	SysCcyInd  bool `xml:"SysCcyInd"`
	ClsrPrdInd bool `xml:"ClsrPrdInd"`
	EvtInd     bool `xml:"EvtInd"`
	SsnPrdInd  bool `xml:"SsnPrdInd"`
	EvtTpInd   bool `xml:"EvtTpInd"`
}

// BusinessDaySearchCriteria2 ...
type BusinessDaySearchCriteria2 struct {
	SysDt   string                         `xml:"SysDt"`
	SysId   []*SystemIdentification2Choice `xml:"SysId"`
	SysCcy  []string                       `xml:"SysCcy"`
	EvtTp   *SystemEventType2Choice        `xml:"EvtTp"`
	ClsrPrd *DateTimePeriod1Choice         `xml:"ClsrPrd"`
}

// CountryCode ...
type CountryCode string

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

// ExternalEnquiryRequestType1Code ...
type ExternalEnquiryRequestType1Code string

// ExternalMarketInfrastructure1Code ...
type ExternalMarketInfrastructure1Code string

// ExternalPaymentControlRequestType1Code ...
type ExternalPaymentControlRequestType1Code string

// GenericIdentification1 ...
type GenericIdentification1 struct {
	Id      string `xml:"Id"`
	SchmeNm string `xml:"SchmeNm"`
	Issr    string `xml:"Issr"`
}

// GetBusinessDayInformationV05 ...
type GetBusinessDayInformationV05 struct {
	MsgHdr          *MessageHeader9       `xml:"MsgHdr"`
	BizDayInfQryDef *BusinessDayQuery2    `xml:"BizDayInfQryDef"`
	SplmtryData     []*SupplementaryData1 `xml:"SplmtryData"`
}

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// MarketInfrastructureIdentification1Choice ...
type MarketInfrastructureIdentification1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// MessageHeader9 ...
type MessageHeader9 struct {
	MsgId   string              `xml:"MsgId"`
	CreDtTm string              `xml:"CreDtTm"`
	ReqTp   *RequestType4Choice `xml:"ReqTp"`
}

// QueryType2Code ...
type QueryType2Code string

// RequestType4Choice ...
type RequestType4Choice struct {
	PmtCtrl string                  `xml:"PmtCtrl"`
	Enqry   string                  `xml:"Enqry"`
	Prtry   *GenericIdentification1 `xml:"Prtry"`
}

// RequestedIndicator ...
type RequestedIndicator bool

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// SystemEventType2Choice ...
type SystemEventType2Choice struct {
	Cd    string                  `xml:"Cd"`
	Prtry *GenericIdentification1 `xml:"Prtry"`
}

// SystemEventType2Code ...
type SystemEventType2Code string

// SystemIdentification2Choice ...
type SystemIdentification2Choice struct {
	MktInfrstrctrId *MarketInfrastructureIdentification1Choice `xml:"MktInfrstrctrId"`
	Ctry            string                                     `xml:"Ctry"`
}
