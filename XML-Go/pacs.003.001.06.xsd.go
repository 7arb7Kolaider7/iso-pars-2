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

// ActiveCurrencyAndAmountSimpleType ...
type ActiveCurrencyAndAmountSimpleType float64

// ActiveCurrencyAndAmount ...
type ActiveCurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// ActiveCurrencyCode ...
type ActiveCurrencyCode string

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

// AmendmentInformationDetails10 ...
type AmendmentInformationDetails10 struct {
	OrgnlMndtId      string                                        `xml:"OrgnlMndtId"`
	OrgnlCdtrSchmeId *PartyIdentification43                        `xml:"OrgnlCdtrSchmeId"`
	OrgnlCdtrAgt     *BranchAndFinancialInstitutionIdentification5 `xml:"OrgnlCdtrAgt"`
	OrgnlCdtrAgtAcct *CashAccount24                                `xml:"OrgnlCdtrAgtAcct"`
	OrgnlDbtr        *PartyIdentification43                        `xml:"OrgnlDbtr"`
	OrgnlDbtrAcct    *CashAccount24                                `xml:"OrgnlDbtrAcct"`
	OrgnlDbtrAgt     *BranchAndFinancialInstitutionIdentification5 `xml:"OrgnlDbtrAgt"`
	OrgnlDbtrAgtAcct *CashAccount24                                `xml:"OrgnlDbtrAgtAcct"`
	OrgnlFnlColltnDt string                                        `xml:"OrgnlFnlColltnDt"`
	OrgnlFrqcy       *Frequency21Choice                            `xml:"OrgnlFrqcy"`
	OrgnlRsn         *MandateSetupReason1Choice                    `xml:"OrgnlRsn"`
}

// AnyBICIdentifier ...
type AnyBICIdentifier string

// Authorisation1Choice ...
type Authorisation1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Authorisation1Code ...
type Authorisation1Code string

// BICFIIdentifier ...
type BICFIIdentifier string

// BaseOneRate ...
type BaseOneRate float64

// BatchBookingIndicator ...
type BatchBookingIndicator bool

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

// CashAccount24 ...
type CashAccount24 struct {
	Id  *AccountIdentification4Choice `xml:"Id"`
	Tp  *CashAccountType2Choice       `xml:"Tp"`
	Ccy string                        `xml:"Ccy"`
	Nm  string                        `xml:"Nm"`
}

// CashAccountType2Choice ...
type CashAccountType2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CategoryPurpose1Choice ...
type CategoryPurpose1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ChargeBearerType1Code ...
type ChargeBearerType1Code string

// Charges2 ...
type Charges2 struct {
	Amt *ActiveOrHistoricCurrencyAndAmount            `xml:"Amt"`
	Agt *BranchAndFinancialInstitutionIdentification5 `xml:"Agt"`
}

// ClearingChannel2Code ...
type ClearingChannel2Code string

// ClearingSystemIdentification2Choice ...
type ClearingSystemIdentification2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ClearingSystemIdentification3Choice ...
type ClearingSystemIdentification3Choice struct {
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

// CreditDebitCode ...
type CreditDebitCode string

// CreditorReferenceInformation2 ...
type CreditorReferenceInformation2 struct {
	Tp  *CreditorReferenceType2 `xml:"Tp"`
	Ref string                  `xml:"Ref"`
}

// CreditorReferenceType1Choice ...
type CreditorReferenceType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CreditorReferenceType2 ...
type CreditorReferenceType2 struct {
	CdOrPrtry *CreditorReferenceType1Choice `xml:"CdOrPrtry"`
	Issr      string                        `xml:"Issr"`
}

// DateAndPlaceOfBirth ...
type DateAndPlaceOfBirth struct {
	BirthDt     string `xml:"BirthDt"`
	PrvcOfBirth string `xml:"PrvcOfBirth"`
	CityOfBirth string `xml:"CityOfBirth"`
	CtryOfBirth string `xml:"CtryOfBirth"`
}

// DatePeriodDetails ...
type DatePeriodDetails struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// DecimalNumber ...
type DecimalNumber float64

// DirectDebitTransaction8 ...
type DirectDebitTransaction8 struct {
	MndtRltdInf *MandateRelatedInformation10 `xml:"MndtRltdInf"`
	CdtrSchmeId *PartyIdentification43       `xml:"CdtrSchmeId"`
	PreNtfctnId string                       `xml:"PreNtfctnId"`
	PreNtfctnDt string                       `xml:"PreNtfctnDt"`
}

// DirectDebitTransactionInformation20 ...
type DirectDebitTransactionInformation20 struct {
	PmtId          *PaymentIdentification3                       `xml:"PmtId"`
	PmtTpInf       *PaymentTypeInformation25                     `xml:"PmtTpInf"`
	IntrBkSttlmAmt *ActiveCurrencyAndAmount                      `xml:"IntrBkSttlmAmt"`
	IntrBkSttlmDt  string                                        `xml:"IntrBkSttlmDt"`
	SttlmPrty      string                                        `xml:"SttlmPrty"`
	InstdAmt       *ActiveOrHistoricCurrencyAndAmount            `xml:"InstdAmt"`
	XchgRate       float64                                       `xml:"XchgRate"`
	ChrgBr         string                                        `xml:"ChrgBr"`
	ChrgsInf       []*Charges2                                   `xml:"ChrgsInf"`
	ReqdColltnDt   string                                        `xml:"ReqdColltnDt"`
	DrctDbtTx      *DirectDebitTransaction8                      `xml:"DrctDbtTx"`
	Cdtr           *PartyIdentification43                        `xml:"Cdtr"`
	CdtrAcct       *CashAccount24                                `xml:"CdtrAcct"`
	CdtrAgt        *BranchAndFinancialInstitutionIdentification5 `xml:"CdtrAgt"`
	CdtrAgtAcct    *CashAccount24                                `xml:"CdtrAgtAcct"`
	UltmtCdtr      *PartyIdentification43                        `xml:"UltmtCdtr"`
	InitgPty       *PartyIdentification43                        `xml:"InitgPty"`
	InstgAgt       *BranchAndFinancialInstitutionIdentification5 `xml:"InstgAgt"`
	InstdAgt       *BranchAndFinancialInstitutionIdentification5 `xml:"InstdAgt"`
	IntrmyAgt1     *BranchAndFinancialInstitutionIdentification5 `xml:"IntrmyAgt1"`
	IntrmyAgt1Acct *CashAccount24                                `xml:"IntrmyAgt1Acct"`
	IntrmyAgt2     *BranchAndFinancialInstitutionIdentification5 `xml:"IntrmyAgt2"`
	IntrmyAgt2Acct *CashAccount24                                `xml:"IntrmyAgt2Acct"`
	IntrmyAgt3     *BranchAndFinancialInstitutionIdentification5 `xml:"IntrmyAgt3"`
	IntrmyAgt3Acct *CashAccount24                                `xml:"IntrmyAgt3Acct"`
	Dbtr           *PartyIdentification43                        `xml:"Dbtr"`
	DbtrAcct       *CashAccount24                                `xml:"DbtrAcct"`
	DbtrAgt        *BranchAndFinancialInstitutionIdentification5 `xml:"DbtrAgt"`
	DbtrAgtAcct    *CashAccount24                                `xml:"DbtrAgtAcct"`
	UltmtDbtr      *PartyIdentification43                        `xml:"UltmtDbtr"`
	Purp           *Purpose2Choice                               `xml:"Purp"`
	RgltryRptg     []*RegulatoryReporting3                       `xml:"RgltryRptg"`
	RltdRmtInf     []*RemittanceLocation4                        `xml:"RltdRmtInf"`
	RmtInf         *RemittanceInformation11                      `xml:"RmtInf"`
	SplmtryData    []*SupplementaryData1                         `xml:"SplmtryData"`
}

// DiscountAmountAndType1 ...
type DiscountAmountAndType1 struct {
	Tp  *DiscountAmountType1Choice         `xml:"Tp"`
	Amt *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
}

// DiscountAmountType1Choice ...
type DiscountAmountType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// DocumentAdjustment1 ...
type DocumentAdjustment1 struct {
	Amt       *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Rsn       string                             `xml:"Rsn"`
	AddtlInf  string                             `xml:"AddtlInf"`
}

// DocumentLineIdentification1 ...
type DocumentLineIdentification1 struct {
	Tp     *DocumentLineType1 `xml:"Tp"`
	Nb     string             `xml:"Nb"`
	RltdDt string             `xml:"RltdDt"`
}

// DocumentLineInformation1 ...
type DocumentLineInformation1 struct {
	Id   []*DocumentLineIdentification1 `xml:"Id"`
	Desc string                         `xml:"Desc"`
	Amt  *RemittanceAmount3             `xml:"Amt"`
}

// DocumentLineType1 ...
type DocumentLineType1 struct {
	CdOrPrtry *DocumentLineType1Choice `xml:"CdOrPrtry"`
	Issr      string                   `xml:"Issr"`
}

// DocumentLineType1Choice ...
type DocumentLineType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// DocumentType3Code ...
type DocumentType3Code string

// DocumentType6Code ...
type DocumentType6Code string

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalCashAccountType1Code ...
type ExternalCashAccountType1Code string

// ExternalCashClearingSystem1Code ...
type ExternalCashClearingSystem1Code string

// ExternalCategoryPurpose1Code ...
type ExternalCategoryPurpose1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalDiscountAmountType1Code ...
type ExternalDiscountAmountType1Code string

// ExternalDocumentLineType1Code ...
type ExternalDocumentLineType1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalGarnishmentType1Code ...
type ExternalGarnishmentType1Code string

// ExternalLocalInstrument1Code ...
type ExternalLocalInstrument1Code string

// ExternalMandateSetupReason1Code ...
type ExternalMandateSetupReason1Code string

// ExternalOrganisationIdentification1Code ...
type ExternalOrganisationIdentification1Code string

// ExternalPersonIdentification1Code ...
type ExternalPersonIdentification1Code string

// ExternalPurpose1Code ...
type ExternalPurpose1Code string

// ExternalServiceLevel1Code ...
type ExternalServiceLevel1Code string

// ExternalTaxAmountType1Code ...
type ExternalTaxAmountType1Code string

// FIToFICustomerDirectDebitV06 ...
type FIToFICustomerDirectDebitV06 struct {
	GrpHdr       *GroupHeader50                         `xml:"GrpHdr"`
	DrctDbtTxInf []*DirectDebitTransactionInformation20 `xml:"DrctDbtTxInf"`
	SplmtryData  []*SupplementaryData1                  `xml:"SplmtryData"`
}

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

// Frequency21Choice ...
type Frequency21Choice struct {
	Tp  string            `xml:"Tp"`
	Prd *FrequencyPeriod1 `xml:"Prd"`
}

// Frequency6Code ...
type Frequency6Code string

// FrequencyPeriod1 ...
type FrequencyPeriod1 struct {
	Tp        string  `xml:"Tp"`
	CntPerPrd float64 `xml:"CntPerPrd"`
}

// Garnishment1 ...
type Garnishment1 struct {
	Tp                *GarnishmentType1                  `xml:"Tp"`
	Grnshee           *PartyIdentification43             `xml:"Grnshee"`
	GrnshmtAdmstr     *PartyIdentification43             `xml:"GrnshmtAdmstr"`
	RefNb             string                             `xml:"RefNb"`
	Dt                string                             `xml:"Dt"`
	RmtdAmt           *ActiveOrHistoricCurrencyAndAmount `xml:"RmtdAmt"`
	FmlyMdclInsrncInd bool                               `xml:"FmlyMdclInsrncInd"`
	MplyeeTermntnInd  bool                               `xml:"MplyeeTermntnInd"`
}

// GarnishmentType1 ...
type GarnishmentType1 struct {
	CdOrPrtry *GarnishmentType1Choice `xml:"CdOrPrtry"`
	Issr      string                  `xml:"Issr"`
}

// GarnishmentType1Choice ...
type GarnishmentType1Choice struct {
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

// GroupHeader50 ...
type GroupHeader50 struct {
	MsgId             string                                        `xml:"MsgId"`
	CreDtTm           string                                        `xml:"CreDtTm"`
	Authstn           []*Authorisation1Choice                       `xml:"Authstn"`
	BtchBookg         bool                                          `xml:"BtchBookg"`
	NbOfTxs           string                                        `xml:"NbOfTxs"`
	CtrlSum           float64                                       `xml:"CtrlSum"`
	TtlIntrBkSttlmAmt *ActiveCurrencyAndAmount                      `xml:"TtlIntrBkSttlmAmt"`
	IntrBkSttlmDt     string                                        `xml:"IntrBkSttlmDt"`
	SttlmInf          *SettlementInstruction2                       `xml:"SttlmInf"`
	PmtTpInf          *PaymentTypeInformation25                     `xml:"PmtTpInf"`
	InstgAgt          *BranchAndFinancialInstitutionIdentification5 `xml:"InstgAgt"`
	InstdAgt          *BranchAndFinancialInstitutionIdentification5 `xml:"InstdAgt"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// LocalInstrument2Choice ...
type LocalInstrument2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// MandateRelatedInformation10 ...
type MandateRelatedInformation10 struct {
	MndtId        string                         `xml:"MndtId"`
	DtOfSgntr     string                         `xml:"DtOfSgntr"`
	AmdmntInd     bool                           `xml:"AmdmntInd"`
	AmdmntInfDtls *AmendmentInformationDetails10 `xml:"AmdmntInfDtls"`
	ElctrncSgntr  string                         `xml:"ElctrncSgntr"`
	FrstColltnDt  string                         `xml:"FrstColltnDt"`
	FnlColltnDt   string                         `xml:"FnlColltnDt"`
	Frqcy         *Frequency21Choice             `xml:"Frqcy"`
	Rsn           *MandateSetupReason1Choice     `xml:"Rsn"`
}

// MandateSetupReason1Choice ...
type MandateSetupReason1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Max1025Text ...
type Max1025Text string

// Max10Text ...
type Max10Text string

// Max128Text ...
type Max128Text string

// Max140Text ...
type Max140Text string

// Max15NumericText ...
type Max15NumericText string

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

// Max4Text ...
type Max4Text string

// Max70Text ...
type Max70Text string

// NameAndAddress10 ...
type NameAndAddress10 struct {
	Nm  string          `xml:"Nm"`
	Adr *PostalAddress6 `xml:"Adr"`
}

// NamePrefix1Code ...
type NamePrefix1Code string

// Number ...
type Number float64

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

// Party11Choice ...
type Party11Choice struct {
	OrgId  *OrganisationIdentification8 `xml:"OrgId"`
	PrvtId *PersonIdentification5       `xml:"PrvtId"`
}

// PartyIdentification43 ...
type PartyIdentification43 struct {
	Nm        string           `xml:"Nm"`
	PstlAdr   *PostalAddress6  `xml:"PstlAdr"`
	Id        *Party11Choice   `xml:"Id"`
	CtryOfRes string           `xml:"CtryOfRes"`
	CtctDtls  *ContactDetails2 `xml:"CtctDtls"`
}

// PaymentIdentification3 ...
type PaymentIdentification3 struct {
	InstrId    string `xml:"InstrId"`
	EndToEndId string `xml:"EndToEndId"`
	TxId       string `xml:"TxId"`
	ClrSysRef  string `xml:"ClrSysRef"`
}

// PaymentTypeInformation25 ...
type PaymentTypeInformation25 struct {
	InstrPrty string                  `xml:"InstrPrty"`
	ClrChanl  string                  `xml:"ClrChanl"`
	SvcLvl    *ServiceLevel8Choice    `xml:"SvcLvl"`
	LclInstrm *LocalInstrument2Choice `xml:"LclInstrm"`
	SeqTp     string                  `xml:"SeqTp"`
	CtgyPurp  *CategoryPurpose1Choice `xml:"CtgyPurp"`
}

// PercentageRate ...
type PercentageRate float64

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

// Priority2Code ...
type Priority2Code string

// Priority3Code ...
type Priority3Code string

// Purpose2Choice ...
type Purpose2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ReferredDocumentInformation7 ...
type ReferredDocumentInformation7 struct {
	Tp       *ReferredDocumentType4      `xml:"Tp"`
	Nb       string                      `xml:"Nb"`
	RltdDt   string                      `xml:"RltdDt"`
	LineDtls []*DocumentLineInformation1 `xml:"LineDtls"`
}

// ReferredDocumentType3Choice ...
type ReferredDocumentType3Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ReferredDocumentType4 ...
type ReferredDocumentType4 struct {
	CdOrPrtry *ReferredDocumentType3Choice `xml:"CdOrPrtry"`
	Issr      string                       `xml:"Issr"`
}

// RegulatoryAuthority2 ...
type RegulatoryAuthority2 struct {
	Nm   string `xml:"Nm"`
	Ctry string `xml:"Ctry"`
}

// RegulatoryReporting3 ...
type RegulatoryReporting3 struct {
	DbtCdtRptgInd string                            `xml:"DbtCdtRptgInd"`
	Authrty       *RegulatoryAuthority2             `xml:"Authrty"`
	Dtls          []*StructuredRegulatoryReporting3 `xml:"Dtls"`
}

// RegulatoryReportingType1Code ...
type RegulatoryReportingType1Code string

// RemittanceAmount2 ...
type RemittanceAmount2 struct {
	DuePyblAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"DuePyblAmt"`
	DscntApldAmt      []*DiscountAmountAndType1          `xml:"DscntApldAmt"`
	CdtNoteAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"CdtNoteAmt"`
	TaxAmt            []*TaxAmountAndType1               `xml:"TaxAmt"`
	AdjstmntAmtAndRsn []*DocumentAdjustment1             `xml:"AdjstmntAmtAndRsn"`
	RmtdAmt           *ActiveOrHistoricCurrencyAndAmount `xml:"RmtdAmt"`
}

// RemittanceAmount3 ...
type RemittanceAmount3 struct {
	DuePyblAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"DuePyblAmt"`
	DscntApldAmt      []*DiscountAmountAndType1          `xml:"DscntApldAmt"`
	CdtNoteAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"CdtNoteAmt"`
	TaxAmt            []*TaxAmountAndType1               `xml:"TaxAmt"`
	AdjstmntAmtAndRsn []*DocumentAdjustment1             `xml:"AdjstmntAmtAndRsn"`
	RmtdAmt           *ActiveOrHistoricCurrencyAndAmount `xml:"RmtdAmt"`
}

// RemittanceInformation11 ...
type RemittanceInformation11 struct {
	Ustrd []string                             `xml:"Ustrd"`
	Strd  []*StructuredRemittanceInformation13 `xml:"Strd"`
}

// RemittanceLocation4 ...
type RemittanceLocation4 struct {
	RmtId       string                        `xml:"RmtId"`
	RmtLctnDtls []*RemittanceLocationDetails1 `xml:"RmtLctnDtls"`
}

// RemittanceLocationDetails1 ...
type RemittanceLocationDetails1 struct {
	Mtd        string            `xml:"Mtd"`
	ElctrncAdr string            `xml:"ElctrncAdr"`
	PstlAdr    *NameAndAddress10 `xml:"PstlAdr"`
}

// RemittanceLocationMethod2Code ...
type RemittanceLocationMethod2Code string

// SequenceType3Code ...
type SequenceType3Code string

// ServiceLevel8Choice ...
type ServiceLevel8Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SettlementInstruction2 ...
type SettlementInstruction2 struct {
	SttlmMtd  string                               `xml:"SttlmMtd"`
	SttlmAcct *CashAccount24                       `xml:"SttlmAcct"`
	ClrSys    *ClearingSystemIdentification3Choice `xml:"ClrSys"`
}

// SettlementMethod2Code ...
type SettlementMethod2Code string

// StructuredRegulatoryReporting3 ...
type StructuredRegulatoryReporting3 struct {
	Tp   string                             `xml:"Tp"`
	Dt   string                             `xml:"Dt"`
	Ctry string                             `xml:"Ctry"`
	Cd   string                             `xml:"Cd"`
	Amt  *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	Inf  []string                           `xml:"Inf"`
}

// StructuredRemittanceInformation13 ...
type StructuredRemittanceInformation13 struct {
	RfrdDocInf  []*ReferredDocumentInformation7 `xml:"RfrdDocInf"`
	RfrdDocAmt  *RemittanceAmount2              `xml:"RfrdDocAmt"`
	CdtrRefInf  *CreditorReferenceInformation2  `xml:"CdtrRefInf"`
	Invcr       *PartyIdentification43          `xml:"Invcr"`
	Invcee      *PartyIdentification43          `xml:"Invcee"`
	TaxRmt      *TaxInformation4                `xml:"TaxRmt"`
	GrnshmtRmt  *Garnishment1                   `xml:"GrnshmtRmt"`
	AddtlRmtInf []string                        `xml:"AddtlRmtInf"`
}

// SupplementaryData1 ...
type SupplementaryData1 struct {
	PlcAndNm string                      `xml:"PlcAndNm"`
	Envlp    *SupplementaryDataEnvelope1 `xml:"Envlp"`
}

// SupplementaryDataEnvelope1 ...
type SupplementaryDataEnvelope1 struct {
}

// TaxAmount1 ...
type TaxAmount1 struct {
	Rate         float64                            `xml:"Rate"`
	TaxblBaseAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TaxblBaseAmt"`
	TtlAmt       *ActiveOrHistoricCurrencyAndAmount `xml:"TtlAmt"`
	Dtls         []*TaxRecordDetails1               `xml:"Dtls"`
}

// TaxAmountAndType1 ...
type TaxAmountAndType1 struct {
	Tp  *TaxAmountType1Choice              `xml:"Tp"`
	Amt *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
}

// TaxAmountType1Choice ...
type TaxAmountType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// TaxAuthorisation1 ...
type TaxAuthorisation1 struct {
	Titl string `xml:"Titl"`
	Nm   string `xml:"Nm"`
}

// TaxInformation4 ...
type TaxInformation4 struct {
	Cdtr            *TaxParty1                         `xml:"Cdtr"`
	Dbtr            *TaxParty2                         `xml:"Dbtr"`
	UltmtDbtr       *TaxParty2                         `xml:"UltmtDbtr"`
	AdmstnZone      string                             `xml:"AdmstnZone"`
	RefNb           string                             `xml:"RefNb"`
	Mtd             string                             `xml:"Mtd"`
	TtlTaxblBaseAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TtlTaxblBaseAmt"`
	TtlTaxAmt       *ActiveOrHistoricCurrencyAndAmount `xml:"TtlTaxAmt"`
	Dt              string                             `xml:"Dt"`
	SeqNb           float64                            `xml:"SeqNb"`
	Rcrd            []*TaxRecord1                      `xml:"Rcrd"`
}

// TaxParty1 ...
type TaxParty1 struct {
	TaxId  string `xml:"TaxId"`
	RegnId string `xml:"RegnId"`
	TaxTp  string `xml:"TaxTp"`
}

// TaxParty2 ...
type TaxParty2 struct {
	TaxId   string             `xml:"TaxId"`
	RegnId  string             `xml:"RegnId"`
	TaxTp   string             `xml:"TaxTp"`
	Authstn *TaxAuthorisation1 `xml:"Authstn"`
}

// TaxPeriod1 ...
type TaxPeriod1 struct {
	Yr     string             `xml:"Yr"`
	Tp     string             `xml:"Tp"`
	FrToDt *DatePeriodDetails `xml:"FrToDt"`
}

// TaxRecord1 ...
type TaxRecord1 struct {
	Tp       string      `xml:"Tp"`
	Ctgy     string      `xml:"Ctgy"`
	CtgyDtls string      `xml:"CtgyDtls"`
	DbtrSts  string      `xml:"DbtrSts"`
	CertId   string      `xml:"CertId"`
	FrmsCd   string      `xml:"FrmsCd"`
	Prd      *TaxPeriod1 `xml:"Prd"`
	TaxAmt   *TaxAmount1 `xml:"TaxAmt"`
	AddtlInf string      `xml:"AddtlInf"`
}

// TaxRecordDetails1 ...
type TaxRecordDetails1 struct {
	Prd *TaxPeriod1                        `xml:"Prd"`
	Amt *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
}

// TaxRecordPeriod1Code ...
type TaxRecordPeriod1Code string

// TrueFalseIndicator ...
type TrueFalseIndicator bool
