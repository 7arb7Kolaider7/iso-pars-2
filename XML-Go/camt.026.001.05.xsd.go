package schema

// Document ...
type Document *Document

// AMLIndicator ...
type AMLIndicator bool

// ActiveOrHistoricCurrencyAndAmountSimpleType ...
type ActiveOrHistoricCurrencyAndAmountSimpleType float64

// ActiveOrHistoricCurrencyAndAmount ...
type ActiveOrHistoricCurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveOrHistoricCurrencyCode ...
type ActiveOrHistoricCurrencyCode string

// AddressType2Code ...
type AddressType2Code string

// AnyBICIdentifier ...
type AnyBICIdentifier string

// BICFIIdentifier ...
type BICFIIdentifier string

// BranchAndFinancialInstitutionIdentification5 ...
type BranchAndFinancialInstitutionIdentification5 struct {
	FinInstnId *FinancialInstitutionIdentification8 `xml:"FinInstnId"`
	BrnchId    *BranchData2                         `xml:"BrnchId"`
}

// BranchData2 ...
type BranchData2 struct {
	Id      string          `xml:"Id"`
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress6 `xml:"PstlAdr"`
}

// Case3 ...
type Case3 struct {
	Id             string         `xml:"Id"`
	Cretr          *Party12Choice `xml:"Cretr"`
	ReopCaseIndctn bool           `xml:"ReopCaseIndctn"`
}

// CaseAssignment3 ...
type CaseAssignment3 struct {
	Id      string         `xml:"Id"`
	Assgnr  *Party12Choice `xml:"Assgnr"`
	Assgne  *Party12Choice `xml:"Assgne"`
	CreDtTm string         `xml:"CreDtTm"`
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

// ContactDetails2 ...
type ContactDetails2 struct {
	NmPrfx   string `xml:"NmPrfx"`
	Nm       string `xml:"Nm"`
	PhneNb   string `xml:"PhneNb"`
	MobNb    string `xml:"MobNb"`
	FaxNb    string `xml:"FaxNb"`
	EmailAdr string `xml:"EmailAdr"`
	Othr     string `xml:"Othr"`
}

// CountryCode ...
type CountryCode string

// DateAndDateTimeChoice ...
type DateAndDateTimeChoice struct {
	Dt   string `xml:"Dt"`
	DtTm string `xml:"DtTm"`
}

// DateAndPlaceOfBirth ...
type DateAndPlaceOfBirth struct {
	BirthDt     string `xml:"BirthDt"`
	PrvcOfBirth string `xml:"PrvcOfBirth"`
	CityOfBirth string `xml:"CityOfBirth"`
	CtryOfBirth string `xml:"CtryOfBirth"`
}

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalOrganisationIdentification1Code ...
type ExternalOrganisationIdentification1Code string

// ExternalPersonIdentification1Code ...
type ExternalPersonIdentification1Code string

// FinancialIdentificationSchemeName1Choice ...
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// FinancialInstitutionIdentification8 ...
type FinancialInstitutionIdentification8 struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	Nm          string                               `xml:"Nm"`
	PstlAdr     *PostalAddress6                      `xml:"PstlAdr"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
}

// GenericFinancialIdentification1 ...
type GenericFinancialIdentification1 struct {
	Id      string                                    `xml:"Id"`
	SchmeNm *FinancialIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                    `xml:"Issr"`
}

// GenericOrganisationIdentification1 ...
type GenericOrganisationIdentification1 struct {
	Id      string                                       `xml:"Id"`
	SchmeNm *OrganisationIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                       `xml:"Issr"`
}

// GenericPersonIdentification1 ...
type GenericPersonIdentification1 struct {
	Id      string                                 `xml:"Id"`
	SchmeNm *PersonIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                 `xml:"Issr"`
}

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// Max140Text ...
type Max140Text string

// Max16Text ...
type Max16Text string

// Max2048Text ...
type Max2048Text string

// Max350Text ...
type Max350Text string

// Max35Text ...
type Max35Text string

// Max70Text ...
type Max70Text string

// MissingOrIncorrectInformation3 ...
type MissingOrIncorrectInformation3 struct {
	AMLReq     bool                       `xml:"AMLReq"`
	MssngInf   []*UnableToApplyMissing1   `xml:"MssngInf"`
	IncrrctInf []*UnableToApplyIncorrect1 `xml:"IncrrctInf"`
}

// NamePrefix1Code ...
type NamePrefix1Code string

// OrganisationIdentification8 ...
type OrganisationIdentification8 struct {
	AnyBIC string                                `xml:"AnyBIC"`
	Othr   []*GenericOrganisationIdentification1 `xml:"Othr"`
}

// OrganisationIdentificationSchemeName1Choice ...
type OrganisationIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// OriginalGroupInformation3 ...
type OriginalGroupInformation3 struct {
	OrgnlMsgId   string `xml:"OrgnlMsgId"`
	OrgnlMsgNmId string `xml:"OrgnlMsgNmId"`
	OrgnlCreDtTm string `xml:"OrgnlCreDtTm"`
}

// Party11Choice ...
type Party11Choice struct {
	OrgId  *OrganisationIdentification8 `xml:"OrgId"`
	PrvtId *PersonIdentification5       `xml:"PrvtId"`
}

// Party12Choice ...
type Party12Choice struct {
	Pty *PartyIdentification43                        `xml:"Pty"`
	Agt *BranchAndFinancialInstitutionIdentification5 `xml:"Agt"`
}

// PartyIdentification43 ...
type PartyIdentification43 struct {
	Nm        string           `xml:"Nm"`
	PstlAdr   *PostalAddress6  `xml:"PstlAdr"`
	Id        *Party11Choice   `xml:"Id"`
	CtryOfRes string           `xml:"CtryOfRes"`
	CtctDtls  *ContactDetails2 `xml:"CtctDtls"`
}

// PersonIdentification5 ...
type PersonIdentification5 struct {
	DtAndPlcOfBirth *DateAndPlaceOfBirth            `xml:"DtAndPlcOfBirth"`
	Othr            []*GenericPersonIdentification1 `xml:"Othr"`
}

// PersonIdentificationSchemeName1Choice ...
type PersonIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// PhoneNumber ...
type PhoneNumber string

// PostalAddress6 ...
type PostalAddress6 struct {
	AdrTp       string   `xml:"AdrTp"`
	Dept        string   `xml:"Dept"`
	SubDept     string   `xml:"SubDept"`
	StrtNm      string   `xml:"StrtNm"`
	BldgNb      string   `xml:"BldgNb"`
	PstCd       string   `xml:"PstCd"`
	TwnNm       string   `xml:"TwnNm"`
	CtrySubDvsn string   `xml:"CtrySubDvsn"`
	Ctry        string   `xml:"Ctry"`
	AdrLine     []string `xml:"AdrLine"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// TrueFalseIndicator ...
type TrueFalseIndicator bool

// UnableToApplyIncorrect1 ...
type UnableToApplyIncorrect1 struct {
	Cd              string `xml:"Cd"`
	AddtlIncrrctInf string `xml:"AddtlIncrrctInf"`
}

// UnableToApplyIncorrectInformation4Code ...
type UnableToApplyIncorrectInformation4Code string

// UnableToApplyJustification3Choice ...
type UnableToApplyJustification3Choice struct {
	AnyInf            bool                            `xml:"AnyInf"`
	MssngOrIncrrctInf *MissingOrIncorrectInformation3 `xml:"MssngOrIncrrctInf"`
	PssblDplctInstr   bool                            `xml:"PssblDplctInstr"`
}

// UnableToApplyMissing1 ...
type UnableToApplyMissing1 struct {
	Cd            string `xml:"Cd"`
	AddtlMssngInf string `xml:"AddtlMssngInf"`
}

// UnableToApplyMissingInformation3Code ...
type UnableToApplyMissingInformation3Code string

// UnableToApplyV05 ...
type UnableToApplyV05 struct {
	Assgnmt     *CaseAssignment3                   `xml:"Assgnmt"`
	Case        *Case3                             `xml:"Case"`
	Undrlyg     *UnderlyingTransaction3Choice      `xml:"Undrlyg"`
	Justfn      *UnableToApplyJustification3Choice `xml:"Justfn"`
	SplmtryData []*SupplementaryData1              `xml:"SplmtryData"`
}

// UnderlyingGroupInformation1 ...
type UnderlyingGroupInformation1 struct {
	OrgnlMsgId         string `xml:"OrgnlMsgId"`
	OrgnlMsgNmId       string `xml:"OrgnlMsgNmId"`
	OrgnlCreDtTm       string `xml:"OrgnlCreDtTm"`
	OrgnlMsgDlvryChanl string `xml:"OrgnlMsgDlvryChanl"`
}

// UnderlyingPaymentInstruction3 ...
type UnderlyingPaymentInstruction3 struct {
	OrgnlGrpInf     *UnderlyingGroupInformation1       `xml:"OrgnlGrpInf"`
	OrgnlPmtInfId   string                             `xml:"OrgnlPmtInfId"`
	OrgnlInstrId    string                             `xml:"OrgnlInstrId"`
	OrgnlEndToEndId string                             `xml:"OrgnlEndToEndId"`
	OrgnlInstdAmt   *ActiveOrHistoricCurrencyAndAmount `xml:"OrgnlInstdAmt"`
	ReqdExctnDt     *DateAndDateTimeChoice             `xml:"ReqdExctnDt"`
	ReqdColltnDt    string                             `xml:"ReqdColltnDt"`
}

// UnderlyingPaymentTransaction2 ...
type UnderlyingPaymentTransaction2 struct {
	OrgnlGrpInf         *UnderlyingGroupInformation1       `xml:"OrgnlGrpInf"`
	OrgnlInstrId        string                             `xml:"OrgnlInstrId"`
	OrgnlEndToEndId     string                             `xml:"OrgnlEndToEndId"`
	OrgnlTxId           string                             `xml:"OrgnlTxId"`
	OrgnlIntrBkSttlmAmt *ActiveOrHistoricCurrencyAndAmount `xml:"OrgnlIntrBkSttlmAmt"`
	OrgnlIntrBkSttlmDt  string                             `xml:"OrgnlIntrBkSttlmDt"`
}

// UnderlyingStatementEntry1 ...
type UnderlyingStatementEntry1 struct {
	OrgnlGrpInf *OriginalGroupInformation3 `xml:"OrgnlGrpInf"`
	OrgnlStmtId string                     `xml:"OrgnlStmtId"`
	OrgnlNtryId string                     `xml:"OrgnlNtryId"`
}

// UnderlyingTransaction3Choice ...
type UnderlyingTransaction3Choice struct {
	Initn    *UnderlyingPaymentInstruction3 `xml:"Initn"`
	IntrBk   *UnderlyingPaymentTransaction2 `xml:"IntrBk"`
	StmtNtry *UnderlyingStatementEntry1     `xml:"StmtNtry"`
}

// YesNoIndicator ...
type YesNoIndicator bool
