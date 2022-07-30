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

// AmountType4Choice ...
type AmountType4Choice struct {
	InstdAmt *ActiveOrHistoricCurrencyAndAmount `xml:"InstdAmt"`
	EqvtAmt  *EquivalentAmount2                 `xml:"EqvtAmt"`
}

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

// CancellationIndividualStatus1Code ...
type CancellationIndividualStatus1Code string

// CancellationStatusReason2 ...
type CancellationStatusReason2 struct {
	Orgtr    *PartyIdentification43           `xml:"Orgtr"`
	Rsn      *CancellationStatusReason2Choice `xml:"Rsn"`
	AddtlInf []string                         `xml:"AddtlInf"`
}

// CancellationStatusReason2Choice ...
type CancellationStatusReason2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
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

// ChargeType3Choice ...
type ChargeType3Choice struct {
	Cd    string                  `xml:"Cd"`
	Prtry *GenericIdentification3 `xml:"Prtry"`
}

// Charges3 ...
type Charges3 struct {
	TtlChrgsAndTaxAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TtlChrgsAndTaxAmt"`
	Rcrd              []*ChargesRecord1                  `xml:"Rcrd"`
}

// ChargesRecord1 ...
type ChargesRecord1 struct {
	Amt       *ActiveOrHistoricCurrencyAndAmount            `xml:"Amt"`
	CdtDbtInd string                                        `xml:"CdtDbtInd"`
	Tp        *ChargeType3Choice                            `xml:"Tp"`
	Rate      float64                                       `xml:"Rate"`
	Br        string                                        `xml:"Br"`
	Agt       *BranchAndFinancialInstitutionIdentification5 `xml:"Agt"`
	Tax       *TaxCharges2                                  `xml:"Tax"`
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

// DatePeriodDetails ...
type DatePeriodDetails struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// DecimalNumber ...
type DecimalNumber float64

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

// EquivalentAmount2 ...
type EquivalentAmount2 struct {
	Amt      *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CcyOfTrf string                             `xml:"CcyOfTrf"`
}

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalCashAccountType1Code ...
type ExternalCashAccountType1Code string

// ExternalCashClearingSystem1Code ...
type ExternalCashClearingSystem1Code string

// ExternalCategoryPurpose1Code ...
type ExternalCategoryPurpose1Code string

// ExternalChargeType1Code ...
type ExternalChargeType1Code string

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

// InvestigationStatus3Choice ...
type InvestigationStatus3Choice struct {
	Conf           string   `xml:"Conf"`
	RjctdMod       []string `xml:"RjctdMod"`
	DplctOf        *Case3   `xml:"DplctOf"`
	AssgnmtCxlConf bool     `xml:"AssgnmtCxlConf"`
}

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

// Max350Text ...
type Max350Text string

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

// Number ...
type Number float64

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

// OriginalGroupHeader5 ...
type OriginalGroupHeader5 struct {
	OrgnlGrpCxlId    string                            `xml:"OrgnlGrpCxlId"`
	RslvdCase        *Case3                            `xml:"RslvdCase"`
	OrgnlMsgId       string                            `xml:"OrgnlMsgId"`
	OrgnlMsgNmId     string                            `xml:"OrgnlMsgNmId"`
	OrgnlCreDtTm     string                            `xml:"OrgnlCreDtTm"`
	OrgnlNbOfTxs     string                            `xml:"OrgnlNbOfTxs"`
	OrgnlCtrlSum     float64                           `xml:"OrgnlCtrlSum"`
	GrpCxlSts        string                            `xml:"GrpCxlSts"`
	CxlStsRsnInf     []*CancellationStatusReason2      `xml:"CxlStsRsnInf"`
	NbOfTxsPerCxlSts []*NumberOfTransactionsPerStatus1 `xml:"NbOfTxsPerCxlSts"`
}

// OriginalGroupInformation3 ...
type OriginalGroupInformation3 struct {
	OrgnlMsgId   string `xml:"OrgnlMsgId"`
	OrgnlMsgNmId string `xml:"OrgnlMsgNmId"`
	OrgnlCreDtTm string `xml:"OrgnlCreDtTm"`
}

// OriginalPaymentInstruction17 ...
type OriginalPaymentInstruction17 struct {
	OrgnlPmtInfCxlId string                             `xml:"OrgnlPmtInfCxlId"`
	RslvdCase        *Case3                             `xml:"RslvdCase"`
	OrgnlPmtInfId    string                             `xml:"OrgnlPmtInfId"`
	OrgnlGrpInf      *OriginalGroupInformation3         `xml:"OrgnlGrpInf"`
	OrgnlNbOfTxs     string                             `xml:"OrgnlNbOfTxs"`
	OrgnlCtrlSum     float64                            `xml:"OrgnlCtrlSum"`
	PmtInfCxlSts     string                             `xml:"PmtInfCxlSts"`
	CxlStsRsnInf     []*CancellationStatusReason2       `xml:"CxlStsRsnInf"`
	NbOfTxsPerCxlSts []*NumberOfCancellationsPerStatus1 `xml:"NbOfTxsPerCxlSts"`
	TxInfAndSts      []*PaymentTransaction66            `xml:"TxInfAndSts"`
}

// OriginalTransactionReference22 ...
type OriginalTransactionReference22 struct {
	IntrBkSttlmAmt *ActiveOrHistoricCurrencyAndAmount            `xml:"IntrBkSttlmAmt"`
	Amt            *AmountType4Choice                            `xml:"Amt"`
	IntrBkSttlmDt  string                                        `xml:"IntrBkSttlmDt"`
	ReqdColltnDt   string                                        `xml:"ReqdColltnDt"`
	ReqdExctnDt    string                                        `xml:"ReqdExctnDt"`
	CdtrSchmeId    *PartyIdentification43                        `xml:"CdtrSchmeId"`
	SttlmInf       *SettlementInstruction4                       `xml:"SttlmInf"`
	PmtTpInf       *PaymentTypeInformation25                     `xml:"PmtTpInf"`
	PmtMtd         string                                        `xml:"PmtMtd"`
	MndtRltdInf    *MandateRelatedInformation10                  `xml:"MndtRltdInf"`
	RmtInf         *RemittanceInformation11                      `xml:"RmtInf"`
	UltmtDbtr      *PartyIdentification43                        `xml:"UltmtDbtr"`
	Dbtr           *PartyIdentification43                        `xml:"Dbtr"`
	DbtrAcct       *CashAccount24                                `xml:"DbtrAcct"`
	DbtrAgt        *BranchAndFinancialInstitutionIdentification5 `xml:"DbtrAgt"`
	DbtrAgtAcct    *CashAccount24                                `xml:"DbtrAgtAcct"`
	CdtrAgt        *BranchAndFinancialInstitutionIdentification5 `xml:"CdtrAgt"`
	CdtrAgtAcct    *CashAccount24                                `xml:"CdtrAgtAcct"`
	Cdtr           *PartyIdentification43                        `xml:"Cdtr"`
	CdtrAcct       *CashAccount24                                `xml:"CdtrAcct"`
	UltmtCdtr      *PartyIdentification43                        `xml:"UltmtCdtr"`
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

// PaymentCancellationRejection2Code ...
type PaymentCancellationRejection2Code string

// PaymentMethod4Code ...
type PaymentMethod4Code string

// PaymentTransaction66 ...
type PaymentTransaction66 struct {
	CxlStsId          string                             `xml:"CxlStsId"`
	RslvdCase         *Case3                             `xml:"RslvdCase"`
	OrgnlInstrId      string                             `xml:"OrgnlInstrId"`
	OrgnlEndToEndId   string                             `xml:"OrgnlEndToEndId"`
	TxCxlSts          string                             `xml:"TxCxlSts"`
	CxlStsRsnInf      []*CancellationStatusReason2       `xml:"CxlStsRsnInf"`
	OrgnlInstdAmt     *ActiveOrHistoricCurrencyAndAmount `xml:"OrgnlInstdAmt"`
	OrgnlReqdExctnDt  string                             `xml:"OrgnlReqdExctnDt"`
	OrgnlReqdColltnDt string                             `xml:"OrgnlReqdColltnDt"`
	OrgnlTxRef        *OriginalTransactionReference22    `xml:"OrgnlTxRef"`
}

// PaymentTransaction67 ...
type PaymentTransaction67 struct {
	CxlStsId            string                             `xml:"CxlStsId"`
	RslvdCase           *Case3                             `xml:"RslvdCase"`
	OrgnlGrpInf         *OriginalGroupInformation3         `xml:"OrgnlGrpInf"`
	OrgnlInstrId        string                             `xml:"OrgnlInstrId"`
	OrgnlEndToEndId     string                             `xml:"OrgnlEndToEndId"`
	OrgnlTxId           string                             `xml:"OrgnlTxId"`
	OrgnlClrSysRef      string                             `xml:"OrgnlClrSysRef"`
	TxCxlSts            string                             `xml:"TxCxlSts"`
	CxlStsRsnInf        []*CancellationStatusReason2       `xml:"CxlStsRsnInf"`
	RsltnRltdInf        *ResolutionInformation1            `xml:"RsltnRltdInf"`
	OrgnlIntrBkSttlmAmt *ActiveOrHistoricCurrencyAndAmount `xml:"OrgnlIntrBkSttlmAmt"`
	OrgnlIntrBkSttlmDt  string                             `xml:"OrgnlIntrBkSttlmDt"`
	Assgnr              *Party12Choice                     `xml:"Assgnr"`
	Assgne              *Party12Choice                     `xml:"Assgne"`
	OrgnlTxRef          *OriginalTransactionReference22    `xml:"OrgnlTxRef"`
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

// ResolutionInformation1 ...
type ResolutionInformation1 struct {
	IntrBkSttlmAmt *ActiveOrHistoricCurrencyAndAmount `xml:"IntrBkSttlmAmt"`
	IntrBkSttlmDt  string                             `xml:"IntrBkSttlmDt"`
	ClrChanl       string                             `xml:"ClrChanl"`
}

// ResolutionOfInvestigationV06 ...
type ResolutionOfInvestigationV06 struct {
	Assgnmt      *CaseAssignment3              `xml:"Assgnmt"`
	RslvdCase    *Case3                        `xml:"RslvdCase"`
	Sts          *InvestigationStatus3Choice   `xml:"Sts"`
	CxlDtls      []*UnderlyingTransaction14    `xml:"CxlDtls"`
	StmtDtls     *StatementResolutionEntry2    `xml:"StmtDtls"`
	CrrctnTx     *CorrectiveTransaction1Choice `xml:"CrrctnTx"`
	RsltnRltdInf *ResolutionInformation1       `xml:"RsltnRltdInf"`
	SplmtryData  []*SupplementaryData1         `xml:"SplmtryData"`
}

// SequenceType3Code ...
type SequenceType3Code string

// ServiceLevel8Choice ...
type ServiceLevel8Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SettlementInstruction4 ...
type SettlementInstruction4 struct {
	SttlmMtd             string                                        `xml:"SttlmMtd"`
	SttlmAcct            *CashAccount24                                `xml:"SttlmAcct"`
	ClrSys               *ClearingSystemIdentification3Choice          `xml:"ClrSys"`
	InstgRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification5 `xml:"InstgRmbrsmntAgt"`
	InstgRmbrsmntAgtAcct *CashAccount24                                `xml:"InstgRmbrsmntAgtAcct"`
	InstdRmbrsmntAgt     *BranchAndFinancialInstitutionIdentification5 `xml:"InstdRmbrsmntAgt"`
	InstdRmbrsmntAgtAcct *CashAccount24                                `xml:"InstdRmbrsmntAgtAcct"`
	ThrdRmbrsmntAgt      *BranchAndFinancialInstitutionIdentification5 `xml:"ThrdRmbrsmntAgt"`
	ThrdRmbrsmntAgtAcct  *CashAccount24                                `xml:"ThrdRmbrsmntAgtAcct"`
}

// SettlementMethod1Code ...
type SettlementMethod1Code string

// StatementResolutionEntry2 ...
type StatementResolutionEntry2 struct {
	OrgnlGrpInf *OriginalGroupInformation3         `xml:"OrgnlGrpInf"`
	OrgnlStmtId string                             `xml:"OrgnlStmtId"`
	AcctSvcrRef string                             `xml:"AcctSvcrRef"`
	CrrctdAmt   *ActiveOrHistoricCurrencyAndAmount `xml:"CrrctdAmt"`
	Chrgs       []*Charges3                        `xml:"Chrgs"`
	Purp        *Purpose2Choice                    `xml:"Purp"`
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

// TaxCharges2 ...
type TaxCharges2 struct {
	Id   string                             `xml:"Id"`
	Rate float64                            `xml:"Rate"`
	Amt  *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
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

// TransactionIndividualStatus1Code ...
type TransactionIndividualStatus1Code string

// TrueFalseIndicator ...
type TrueFalseIndicator bool

// UnderlyingTransaction14 ...
type UnderlyingTransaction14 struct {
	OrgnlGrpInfAndSts *OriginalGroupHeader5           `xml:"OrgnlGrpInfAndSts"`
	OrgnlPmtInfAndSts []*OriginalPaymentInstruction17 `xml:"OrgnlPmtInfAndSts"`
	TxInfAndSts       []*PaymentTransaction67         `xml:"TxInfAndSts"`
}

// YesNoIndicator ...
type YesNoIndicator bool
