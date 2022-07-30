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

// AmendmentInformationDetails6 ...
type AmendmentInformationDetails6 struct {
	OrgnlMndtId      string                                        `xml:"OrgnlMndtId"`
	OrgnlCdtrSchmeId *PartyIdentification32                        `xml:"OrgnlCdtrSchmeId"`
	OrgnlCdtrAgt     *BranchAndFinancialInstitutionIdentification4 `xml:"OrgnlCdtrAgt"`
	OrgnlCdtrAgtAcct *CashAccount16                                `xml:"OrgnlCdtrAgtAcct"`
	OrgnlDbtr        *PartyIdentification32                        `xml:"OrgnlDbtr"`
	OrgnlDbtrAcct    *CashAccount16                                `xml:"OrgnlDbtrAcct"`
	OrgnlDbtrAgt     *BranchAndFinancialInstitutionIdentification4 `xml:"OrgnlDbtrAgt"`
	OrgnlDbtrAgtAcct *CashAccount16                                `xml:"OrgnlDbtrAgtAcct"`
	OrgnlFnlColltnDt string                                        `xml:"OrgnlFnlColltnDt"`
	OrgnlFrqcy       string                                        `xml:"OrgnlFrqcy"`
}

// AmountType3Choice ...
type AmountType3Choice struct {
	InstdAmt *ActiveOrHistoricCurrencyAndAmount `xml:"InstdAmt"`
	EqvtAmt  *EquivalentAmount2                 `xml:"EqvtAmt"`
}

// AnyBICIdentifier ...
type AnyBICIdentifier string

// BICIdentifier ...
type BICIdentifier string

// BranchAndFinancialInstitutionIdentification4 ...
type BranchAndFinancialInstitutionIdentification4 struct {
	FinInstnId *FinancialInstitutionIdentification7 `xml:"FinInstnId"`
	BrnchId    *BranchData2                         `xml:"BrnchId"`
}

// BranchData2 ...
type BranchData2 struct {
	Id      string          `xml:"Id"`
	Nm      string          `xml:"Nm"`
	PstlAdr *PostalAddress6 `xml:"PstlAdr"`
}

// CancellationIndividualStatus1Code ...
type CancellationIndividualStatus1Code string

// CancellationStatusReason1Choice ...
type CancellationStatusReason1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CancellationStatusReasonInformation1 ...
type CancellationStatusReasonInformation1 struct {
	Orgtr    *PartyIdentification32           `xml:"Orgtr"`
	Rsn      *CancellationStatusReason1Choice `xml:"Rsn"`
	AddtlInf []string                         `xml:"AddtlInf"`
}

// Case2 ...
type Case2 struct {
	Id             string        `xml:"Id"`
	Cretr          *Party7Choice `xml:"Cretr"`
	ReopCaseIndctn bool          `xml:"ReopCaseIndctn"`
}

// CaseAssignment2 ...
type CaseAssignment2 struct {
	Id      string        `xml:"Id"`
	Assgnr  *Party7Choice `xml:"Assgnr"`
	Assgne  *Party7Choice `xml:"Assgne"`
	CreDtTm string        `xml:"CreDtTm"`
}

// CashAccount16 ...
type CashAccount16 struct {
	Id  *AccountIdentification4Choice `xml:"Id"`
	Tp  *CashAccountType2             `xml:"Tp"`
	Ccy string                        `xml:"Ccy"`
	Nm  string                        `xml:"Nm"`
}

// CashAccountType2 ...
type CashAccountType2 struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CashAccountType4Code ...
type CashAccountType4Code string

// CategoryPurpose1Choice ...
type CategoryPurpose1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ChargeBearerType1Code ...
type ChargeBearerType1Code string

// ChargeType1Code ...
type ChargeType1Code string

// ChargeType2Choice ...
type ChargeType2Choice struct {
	Cd    string                  `xml:"Cd"`
	Prtry *GenericIdentification3 `xml:"Prtry"`
}

// ChargesInformation6 ...
type ChargesInformation6 struct {
	TtlChrgsAndTaxAmt *ActiveOrHistoricCurrencyAndAmount            `xml:"TtlChrgsAndTaxAmt"`
	Amt               *ActiveOrHistoricCurrencyAndAmount            `xml:"Amt"`
	CdtDbtInd         string                                        `xml:"CdtDbtInd"`
	Tp                *ChargeType2Choice                            `xml:"Tp"`
	Rate              float64                                       `xml:"Rate"`
	Br                string                                        `xml:"Br"`
	Pty               *BranchAndFinancialInstitutionIdentification4 `xml:"Pty"`
	Tax               *TaxCharges2                                  `xml:"Tax"`
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

// CorrectiveGroupInformation1 ...
type CorrectiveGroupInformation1 struct {
	MsgId   string `xml:"MsgId"`
	MsgNmId string `xml:"MsgNmId"`
	CreDtTm string `xml:"CreDtTm"`
}

// CorrectiveInterbankTransaction1 ...
type CorrectiveInterbankTransaction1 struct {
	GrpHdr         *CorrectiveGroupInformation1       `xml:"GrpHdr"`
	InstrId        string                             `xml:"InstrId"`
	EndToEndId     string                             `xml:"EndToEndId"`
	TxId           string                             `xml:"TxId"`
	IntrBkSttlmAmt *ActiveOrHistoricCurrencyAndAmount `xml:"IntrBkSttlmAmt"`
	IntrBkSttlmDt  string                             `xml:"IntrBkSttlmDt"`
}

// CorrectivePaymentInitiation1 ...
type CorrectivePaymentInitiation1 struct {
	GrpHdr       *CorrectiveGroupInformation1       `xml:"GrpHdr"`
	PmtInfId     string                             `xml:"PmtInfId"`
	InstrId      string                             `xml:"InstrId"`
	EndToEndId   string                             `xml:"EndToEndId"`
	InstdAmt     *ActiveOrHistoricCurrencyAndAmount `xml:"InstdAmt"`
	ReqdExctnDt  string                             `xml:"ReqdExctnDt"`
	ReqdColltnDt string                             `xml:"ReqdColltnDt"`
}

// CorrectiveTransaction1Choice ...
type CorrectiveTransaction1Choice struct {
	Initn  *CorrectivePaymentInitiation1    `xml:"Initn"`
	IntrBk *CorrectiveInterbankTransaction1 `xml:"IntrBk"`
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

// DecimalNumber ...
type DecimalNumber float64

// DocumentAdjustment1 ...
type DocumentAdjustment1 struct {
	Amt       *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Rsn       string                             `xml:"Rsn"`
	AddtlInf  string                             `xml:"AddtlInf"`
}

// DocumentType3Code ...
type DocumentType3Code string

// DocumentType5Code ...
type DocumentType5Code string

// EquivalentAmount2 ...
type EquivalentAmount2 struct {
	Amt      *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CcyOfTrf string                             `xml:"CcyOfTrf"`
}

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalCashClearingSystem1Code ...
type ExternalCashClearingSystem1Code string

// ExternalCategoryPurpose1Code ...
type ExternalCategoryPurpose1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalLocalInstrument1Code ...
type ExternalLocalInstrument1Code string

// ExternalOrganisationIdentification1Code ...
type ExternalOrganisationIdentification1Code string

// ExternalPersonIdentification1Code ...
type ExternalPersonIdentification1Code string

// ExternalPurpose1Code ...
type ExternalPurpose1Code string

// ExternalServiceLevel1Code ...
type ExternalServiceLevel1Code string

// FinancialIdentificationSchemeName1Choice ...
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// FinancialInstitutionIdentification7 ...
type FinancialInstitutionIdentification7 struct {
	BIC         string                               `xml:"BIC"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	Nm          string                               `xml:"Nm"`
	PstlAdr     *PostalAddress6                      `xml:"PstlAdr"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
}

// Frequency1Code ...
type Frequency1Code string

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

// GenericIdentification3 ...
type GenericIdentification3 struct {
	Id   string `xml:"Id"`
	Issr string `xml:"Issr"`
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

// GroupCancellationStatus1Code ...
type GroupCancellationStatus1Code string

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// InvestigationExecutionConfirmation3Code ...
type InvestigationExecutionConfirmation3Code string

// InvestigationStatus2Choice ...
type InvestigationStatus2Choice struct {
	Conf           string   `xml:"Conf"`
	RjctdMod       []string `xml:"RjctdMod"`
	DplctOf        *Case2   `xml:"DplctOf"`
	AssgnmtCxlConf bool     `xml:"AssgnmtCxlConf"`
}

// LocalInstrument2Choice ...
type LocalInstrument2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// MandateRelatedInformation6 ...
type MandateRelatedInformation6 struct {
	MndtId        string                        `xml:"MndtId"`
	DtOfSgntr     string                        `xml:"DtOfSgntr"`
	AmdmntInd     bool                          `xml:"AmdmntInd"`
	AmdmntInfDtls *AmendmentInformationDetails6 `xml:"AmdmntInfDtls"`
	ElctrncSgntr  string                        `xml:"ElctrncSgntr"`
	FrstColltnDt  string                        `xml:"FrstColltnDt"`
	FnlColltnDt   string                        `xml:"FnlColltnDt"`
	Frqcy         string                        `xml:"Frqcy"`
}

// Max1025Text ...
type Max1025Text string

// Max105Text ...
type Max105Text string

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

// Max35Text ...
type Max35Text string

// Max4Text ...
type Max4Text string

// Max70Text ...
type Max70Text string

// ModificationRejection2Code ...
type ModificationRejection2Code string

// NamePrefix1Code ...
type NamePrefix1Code string

// NumberOfCancellationsPerStatus1 ...
type NumberOfCancellationsPerStatus1 struct {
	DtldNbOfTxs string  `xml:"DtldNbOfTxs"`
	DtldSts     string  `xml:"DtldSts"`
	DtldCtrlSum float64 `xml:"DtldCtrlSum"`
}

// NumberOfTransactionsPerStatus1 ...
type NumberOfTransactionsPerStatus1 struct {
	DtldNbOfTxs string  `xml:"DtldNbOfTxs"`
	DtldSts     string  `xml:"DtldSts"`
	DtldCtrlSum float64 `xml:"DtldCtrlSum"`
}

// OrganisationIdentification4 ...
type OrganisationIdentification4 struct {
	BICOrBEI string                                `xml:"BICOrBEI"`
	Othr     []*GenericOrganisationIdentification1 `xml:"Othr"`
}

// OrganisationIdentificationSchemeName1Choice ...
type OrganisationIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// OriginalGroupInformation24 ...
type OriginalGroupInformation24 struct {
	OrgnlGrpCxlId    string                                  `xml:"OrgnlGrpCxlId"`
	RslvdCase        *Case2                                  `xml:"RslvdCase"`
	OrgnlMsgId       string                                  `xml:"OrgnlMsgId"`
	OrgnlMsgNmId     string                                  `xml:"OrgnlMsgNmId"`
	OrgnlCreDtTm     string                                  `xml:"OrgnlCreDtTm"`
	OrgnlNbOfTxs     string                                  `xml:"OrgnlNbOfTxs"`
	OrgnlCtrlSum     float64                                 `xml:"OrgnlCtrlSum"`
	GrpCxlSts        string                                  `xml:"GrpCxlSts"`
	CxlStsRsnInf     []*CancellationStatusReasonInformation1 `xml:"CxlStsRsnInf"`
	NbOfTxsPerCxlSts []*NumberOfTransactionsPerStatus1       `xml:"NbOfTxsPerCxlSts"`
}

// OriginalGroupInformation3 ...
type OriginalGroupInformation3 struct {
	OrgnlMsgId   string `xml:"OrgnlMsgId"`
	OrgnlMsgNmId string `xml:"OrgnlMsgNmId"`
	OrgnlCreDtTm string `xml:"OrgnlCreDtTm"`
}

// OriginalPaymentInformation3 ...
type OriginalPaymentInformation3 struct {
	OrgnlPmtInfCxlId string                                  `xml:"OrgnlPmtInfCxlId"`
	RslvdCase        *Case2                                  `xml:"RslvdCase"`
	OrgnlPmtInfId    string                                  `xml:"OrgnlPmtInfId"`
	OrgnlGrpInf      *OriginalGroupInformation3              `xml:"OrgnlGrpInf"`
	OrgnlNbOfTxs     string                                  `xml:"OrgnlNbOfTxs"`
	OrgnlCtrlSum     float64                                 `xml:"OrgnlCtrlSum"`
	PmtInfCxlSts     string                                  `xml:"PmtInfCxlSts"`
	CxlStsRsnInf     []*CancellationStatusReasonInformation1 `xml:"CxlStsRsnInf"`
	NbOfTxsPerCxlSts []*NumberOfCancellationsPerStatus1      `xml:"NbOfTxsPerCxlSts"`
	TxInfAndSts      []*PaymentTransactionInformation32      `xml:"TxInfAndSts"`
}

// OriginalTransactionReference13 ...
type OriginalTransactionReference13 struct {
	IntrBkSttlmAmt *ActiveOrHistoricCurrencyAndAmount            `xml:"IntrBkSttlmAmt"`
	Amt            *AmountType3Choice                            `xml:"Amt"`
	IntrBkSttlmDt  string                                        `xml:"IntrBkSttlmDt"`
	ReqdColltnDt   string                                        `xml:"ReqdColltnDt"`
	ReqdExctnDt    string                                        `xml:"ReqdExctnDt"`
	CdtrSchmeId    *PartyIdentification32                        `xml:"CdtrSchmeId"`
	SttlmInf       *SettlementInformation13                      `xml:"SttlmInf"`
	PmtTpInf       *PaymentTypeInformation22                     `xml:"PmtTpInf"`
	PmtMtd         string                                        `xml:"PmtMtd"`
	MndtRltdInf    *MandateRelatedInformation6                   `xml:"MndtRltdInf"`
	RmtInf         *RemittanceInformation5                       `xml:"RmtInf"`
	UltmtDbtr      *PartyIdentification32                        `xml:"UltmtDbtr"`
	Dbtr           *PartyIdentification32                        `xml:"Dbtr"`
	DbtrAcct       *CashAccount16                                `xml:"DbtrAcct"`
	DbtrAgt        *BranchAndFinancialInstitutionIdentification4 `xml:"DbtrAgt"`
	DbtrAgtAcct    *CashAccount16                                `xml:"DbtrAgtAcct"`
	CdtrAgt        *BranchAndFinancialInstitutionIdentification4 `xml:"CdtrAgt"`
	CdtrAgtAcct    *CashAccount16                                `xml:"CdtrAgtAcct"`
	Cdtr           *PartyIdentification32                        `xml:"Cdtr"`
	CdtrAcct       *CashAccount16                                `xml:"CdtrAcct"`
	UltmtCdtr      *PartyIdentification32                        `xml:"UltmtCdtr"`
}

// Party6Choice ...
type Party6Choice struct {
	OrgId  *OrganisationIdentification4 `xml:"OrgId"`
	PrvtId *PersonIdentification5       `xml:"PrvtId"`
}

// Party7Choice ...
type Party7Choice struct {
	Pty *PartyIdentification32                        `xml:"Pty"`
	Agt *BranchAndFinancialInstitutionIdentification4 `xml:"Agt"`
}

// PartyIdentification32 ...
type PartyIdentification32 struct {
	Nm        string           `xml:"Nm"`
	PstlAdr   *PostalAddress6  `xml:"PstlAdr"`
	Id        *Party6Choice    `xml:"Id"`
	CtryOfRes string           `xml:"CtryOfRes"`
	CtctDtls  *ContactDetails2 `xml:"CtctDtls"`
}

// PaymentCancellationRejection1Code ...
type PaymentCancellationRejection1Code string

// PaymentMethod4Code ...
type PaymentMethod4Code string

// PaymentTransactionInformation32 ...
type PaymentTransactionInformation32 struct {
	CxlStsId          string                                  `xml:"CxlStsId"`
	RslvdCase         *Case2                                  `xml:"RslvdCase"`
	OrgnlInstrId      string                                  `xml:"OrgnlInstrId"`
	OrgnlEndToEndId   string                                  `xml:"OrgnlEndToEndId"`
	TxCxlSts          string                                  `xml:"TxCxlSts"`
	CxlStsRsnInf      []*CancellationStatusReasonInformation1 `xml:"CxlStsRsnInf"`
	OrgnlInstdAmt     *ActiveOrHistoricCurrencyAndAmount      `xml:"OrgnlInstdAmt"`
	OrgnlReqdExctnDt  string                                  `xml:"OrgnlReqdExctnDt"`
	OrgnlReqdColltnDt string                                  `xml:"OrgnlReqdColltnDt"`
	OrgnlTxRef        *OriginalTransactionReference13         `xml:"OrgnlTxRef"`
}

// PaymentTransactionInformation33 ...
type PaymentTransactionInformation33 struct {
	CxlStsId            string                                  `xml:"CxlStsId"`
	RslvdCase           *Case2                                  `xml:"RslvdCase"`
	OrgnlGrpInf         *OriginalGroupInformation3              `xml:"OrgnlGrpInf"`
	OrgnlInstrId        string                                  `xml:"OrgnlInstrId"`
	OrgnlEndToEndId     string                                  `xml:"OrgnlEndToEndId"`
	OrgnlTxId           string                                  `xml:"OrgnlTxId"`
	OrgnlClrSysRef      string                                  `xml:"OrgnlClrSysRef"`
	TxCxlSts            string                                  `xml:"TxCxlSts"`
	CxlStsRsnInf        []*CancellationStatusReasonInformation1 `xml:"CxlStsRsnInf"`
	RsltnRltdInf        *ResolutionInformation1                 `xml:"RsltnRltdInf"`
	OrgnlIntrBkSttlmAmt *ActiveOrHistoricCurrencyAndAmount      `xml:"OrgnlIntrBkSttlmAmt"`
	OrgnlIntrBkSttlmDt  string                                  `xml:"OrgnlIntrBkSttlmDt"`
	Assgnr              *Party7Choice                           `xml:"Assgnr"`
	Assgne              *Party7Choice                           `xml:"Assgne"`
	OrgnlTxRef          *OriginalTransactionReference13         `xml:"OrgnlTxRef"`
}

// PaymentTypeInformation22 ...
type PaymentTypeInformation22 struct {
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

// Purpose2Choice ...
type Purpose2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ReferredDocumentInformation3 ...
type ReferredDocumentInformation3 struct {
	Tp     *ReferredDocumentType2 `xml:"Tp"`
	Nb     string                 `xml:"Nb"`
	RltdDt string                 `xml:"RltdDt"`
}

// ReferredDocumentType1Choice ...
type ReferredDocumentType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ReferredDocumentType2 ...
type ReferredDocumentType2 struct {
	CdOrPrtry *ReferredDocumentType1Choice `xml:"CdOrPrtry"`
	Issr      string                       `xml:"Issr"`
}

// RemittanceAmount1 ...
type RemittanceAmount1 struct {
	DuePyblAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"DuePyblAmt"`
	DscntApldAmt      *ActiveOrHistoricCurrencyAndAmount `xml:"DscntApldAmt"`
	CdtNoteAmt        *ActiveOrHistoricCurrencyAndAmount `xml:"CdtNoteAmt"`
	TaxAmt            *ActiveOrHistoricCurrencyAndAmount `xml:"TaxAmt"`
	AdjstmntAmtAndRsn []*DocumentAdjustment1             `xml:"AdjstmntAmtAndRsn"`
	RmtdAmt           *ActiveOrHistoricCurrencyAndAmount `xml:"RmtdAmt"`
}

// RemittanceInformation5 ...
type RemittanceInformation5 struct {
	Ustrd []string                            `xml:"Ustrd"`
	Strd  []*StructuredRemittanceInformation7 `xml:"Strd"`
}

// ResolutionInformation1 ...
type ResolutionInformation1 struct {
	IntrBkSttlmAmt *ActiveOrHistoricCurrencyAndAmount `xml:"IntrBkSttlmAmt"`
	IntrBkSttlmDt  string                             `xml:"IntrBkSttlmDt"`
	ClrChanl       string                             `xml:"ClrChanl"`
}

// ResolutionOfInvestigationV03 ...
type ResolutionOfInvestigationV03 struct {
	Assgnmt      *CaseAssignment2              `xml:"Assgnmt"`
	RslvdCase    *Case2                        `xml:"RslvdCase"`
	Sts          *InvestigationStatus2Choice   `xml:"Sts"`
	CxlDtls      []*UnderlyingTransaction3     `xml:"CxlDtls"`
	StmtDtls     *StatementResolutionEntry1    `xml:"StmtDtls"`
	CrrctnTx     *CorrectiveTransaction1Choice `xml:"CrrctnTx"`
	RsltnRltdInf *ResolutionInformation1       `xml:"RsltnRltdInf"`
}

// SequenceType1Code ...
type SequenceType1Code string

// ServiceLevel8Choice ...
type ServiceLevel8Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SettlementInformation13 ...
type SettlementInformation13 struct {
	SttlmMtd             string                                        `xml:"SttlmMtd"`
	SttlmAcct            *CashAccount16                                `xml:"SttlmAcct"`
	ClrSys               *ClearingSystemIdentification3Choice          `xml:"ClrSys"`
	InstgRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification4 `xml:"InstgRmbrsmntAgt"`
	InstgRmbrsmntAgtAcct *CashAccount16                                `xml:"InstgRmbrsmntAgtAcct"`
	InstdRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification4 `xml:"InstdRmbrsmntAgt"`
	InstdRmbrsmntAgtAcct *CashAccount16                                `xml:"InstdRmbrsmntAgtAcct"`
	ThrdRmbrsmntAgt      *BranchAndFinancialInstitutionIdentification4 `xml:"ThrdRmbrsmntAgt"`
	ThrdRmbrsmntAgtAcct  *CashAccount16                                `xml:"ThrdRmbrsmntAgtAcct"`
}

// SettlementMethod1Code ...
type SettlementMethod1Code string

// StatementResolutionEntry1 ...
type StatementResolutionEntry1 struct {
	OrgnlGrpInf *OriginalGroupInformation3         `xml:"OrgnlGrpInf"`
	OrgnlStmtId string                             `xml:"OrgnlStmtId"`
	AcctSvcrRef string                             `xml:"AcctSvcrRef"`
	CrrctdAmt   *ActiveOrHistoricCurrencyAndAmount `xml:"CrrctdAmt"`
	Chrgs       []*ChargesInformation6             `xml:"Chrgs"`
	Purp        *Purpose2Choice                    `xml:"Purp"`
}

// StructuredRemittanceInformation7 ...
type StructuredRemittanceInformation7 struct {
	RfrdDocInf  []*ReferredDocumentInformation3 `xml:"RfrdDocInf"`
	RfrdDocAmt  *RemittanceAmount1              `xml:"RfrdDocAmt"`
	CdtrRefInf  *CreditorReferenceInformation2  `xml:"CdtrRefInf"`
	Invcr       *PartyIdentification32          `xml:"Invcr"`
	Invcee      *PartyIdentification32          `xml:"Invcee"`
	AddtlRmtInf []string                        `xml:"AddtlRmtInf"`
}

// TaxCharges2 ...
type TaxCharges2 struct {
	Id   string                             `xml:"Id"`
	Rate float64                            `xml:"Rate"`
	Amt  *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
}

// TransactionIndividualStatus1Code ...
type TransactionIndividualStatus1Code string

// TrueFalseIndicator ...
type TrueFalseIndicator bool

// UnderlyingTransaction3 ...
type UnderlyingTransaction3 struct {
	OrgnlGrpInfAndSts *OriginalGroupInformation24        `xml:"OrgnlGrpInfAndSts"`
	OrgnlPmtInfAndSts []*OriginalPaymentInformation3     `xml:"OrgnlPmtInfAndSts"`
	TxInfAndSts       []*PaymentTransactionInformation33 `xml:"TxInfAndSts"`
}

// YesNoIndicator ...
type YesNoIndicator bool
