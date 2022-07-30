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

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalEnquiryRequestType1Code ...
type ExternalEnquiryRequestType1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalPaymentControlRequestType1Code ...
type ExternalPaymentControlRequestType1Code string

// ExternalSystemMemberType1Code ...
type ExternalSystemMemberType1Code string

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

// GenericIdentification1 ...
type GenericIdentification1 struct {
	Id      string `xml:"Id"`
	SchmeNm string `xml:"SchmeNm"`
	Issr    string `xml:"Issr"`
}

// GetMemberV04 ...
type GetMemberV04 struct {
	MsgHdr      *MessageHeader9         `xml:"MsgHdr"`
	MmbQryDef   *MemberQueryDefinition4 `xml:"MmbQryDef"`
	SplmtryData []*SupplementaryData1   `xml:"SplmtryData"`
}

// ISODateTime ...
type ISODateTime string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// MemberCriteria4 ...
type MemberCriteria4 struct {
	NewQryNm string                   `xml:"NewQryNm"`
	SchCrit  []*MemberSearchCriteria4 `xml:"SchCrit"`
	RtrCrit  *MemberReturnCriteria1   `xml:"RtrCrit"`
}

// MemberCriteriaDefinition2Choice ...
type MemberCriteriaDefinition2Choice struct {
	QryNm   string           `xml:"QryNm"`
	NewCrit *MemberCriteria4 `xml:"NewCrit"`
}

// MemberIdentification3Choice ...
type MemberIdentification3Choice struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
}

// MemberQueryDefinition4 ...
type MemberQueryDefinition4 struct {
	QryTp   string                           `xml:"QryTp"`
	MmbCrit *MemberCriteriaDefinition2Choice `xml:"MmbCrit"`
}

// MemberReturnCriteria1 ...
type MemberReturnCriteria1 struct {
	NmInd        bool `xml:"NmInd"`
	MmbRtrAdrInd bool `xml:"MmbRtrAdrInd"`
	AcctInd      bool `xml:"AcctInd"`
	TpInd        bool `xml:"TpInd"`
	StsInd       bool `xml:"StsInd"`
	CtctRefInd   bool `xml:"CtctRefInd"`
	ComAdrInd    bool `xml:"ComAdrInd"`
}

// MemberSearchCriteria4 ...
type MemberSearchCriteria4 struct {
	Id  []*MemberIdentification3Choice `xml:"Id"`
	Tp  []*SystemMemberType1Choice     `xml:"Tp"`
	Sts []*SystemMemberStatus1Choice   `xml:"Sts"`
}

// MemberStatus1Code ...
type MemberStatus1Code string

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
