package schema

// Document ...
type Document *Document

// BusinessInformationCriteria1 ...
type BusinessInformationCriteria1 struct {
	NewQryNm string                                       `xml:"NewQryNm"`
	SchCrit  []*GeneralBusinessInformationSearchCriteria1 `xml:"SchCrit"`
	RtrCrit  *GeneralBusinessInformationReturnCriteria1   `xml:"RtrCrit"`
}

// BusinessInformationQueryDefinition3 ...
type BusinessInformationQueryDefinition3 struct {
	QryTp         string                                               `xml:"QryTp"`
	GnlBizInfCrit *GeneralBusinessInformationCriteriaDefinition1Choice `xml:"GnlBizInfCrit"`
}

// CharacterSearch1Choice ...
type CharacterSearch1Choice struct {
	EQ  string `xml:"EQ"`
	NEQ string `xml:"NEQ"`
	CT  string `xml:"CT"`
	NCT string `xml:"NCT"`
}

// GeneralBusinessInformationCriteriaDefinition1Choice ...
type GeneralBusinessInformationCriteriaDefinition1Choice struct {
	QryNm   string                        `xml:"QryNm"`
	NewCrit *BusinessInformationCriteria1 `xml:"NewCrit"`
}

// GeneralBusinessInformationReturnCriteria1 ...
type GeneralBusinessInformationReturnCriteria1 struct {
	QlfrInd     bool `xml:"QlfrInd"`
	SbjtInd     bool `xml:"SbjtInd"`
	SbjtDtlsInd bool `xml:"SbjtDtlsInd"`
}

// GeneralBusinessInformationSearchCriteria1 ...
type GeneralBusinessInformationSearchCriteria1 struct {
	Ref  []string                     `xml:"Ref"`
	Sbjt []*CharacterSearch1Choice    `xml:"Sbjt"`
	Qlfr []*InformationQualifierType1 `xml:"Qlfr"`
}

// GetGeneralBusinessInformationV04 ...
type GetGeneralBusinessInformationV04 struct {
	MsgHdr          *MessageHeader1                      `xml:"MsgHdr"`
	GnlBizInfQryDef *BusinessInformationQueryDefinition3 `xml:"GnlBizInfQryDef"`
	SplmtryData     []*SupplementaryData1                `xml:"SplmtryData"`
}

// ISODateTime ...
type ISODateTime string

// InformationQualifierType1 ...
type InformationQualifierType1 struct {
	IsFrmtd bool   `xml:"IsFrmtd"`
	Prty    string `xml:"Prty"`
}

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// MessageHeader1 ...
type MessageHeader1 struct {
	MsgId   string `xml:"MsgId"`
	CreDtTm string `xml:"CreDtTm"`
}

// Priority1Code ...
type Priority1Code string

// QueryType2Code ...
type QueryType2Code string

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

// YesNoIndicator ...
type YesNoIndicator bool
