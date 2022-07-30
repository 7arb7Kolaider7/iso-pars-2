package schema

// Document ...
type Document *Document

// AccountIdentification4Choice ...
type AccountIdentification4Choice struct {
	IBAN string                         `xml:"IBAN"`
	Othr *GenericAccountIdentification1 `xml:"Othr"`
}

// AccountInterest3 ...
type AccountInterest3 struct {
	Tp     *InterestType1Choice   `xml:"Tp"`
	Rate   []*Rate3               `xml:"Rate"`
	FrToDt *DateTimePeriodDetails `xml:"FrToDt"`
	Rsn    string                 `xml:"Rsn"`
	Tax    *TaxCharges2           `xml:"Tax"`
}

// AccountSchemeName1Choice ...
type AccountSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// AccountStatement5 ...
type AccountStatement5 struct {
	Id           string                  `xml:"Id"`
	StmtPgntn    *Pagination             `xml:"StmtPgntn"`
	ElctrncSeqNb float64                 `xml:"ElctrncSeqNb"`
	LglSeqNb     float64                 `xml:"LglSeqNb"`
	CreDtTm      string                  `xml:"CreDtTm"`
	FrToDt       *DateTimePeriodDetails  `xml:"FrToDt"`
	CpyDplctInd  string                  `xml:"CpyDplctInd"`
	RptgSrc      *ReportingSource1Choice `xml:"RptgSrc"`
	Acct         *CashAccount25          `xml:"Acct"`
	RltdAcct     *CashAccount24          `xml:"RltdAcct"`
	Intrst       []*AccountInterest3     `xml:"Intrst"`
	Bal          []*CashBalance3         `xml:"Bal"`
	TxsSummry    *TotalTransactions4     `xml:"TxsSummry"`
	Ntry         []*ReportEntry7         `xml:"Ntry"`
	AddtlStmtInf string                  `xml:"AddtlStmtInf"`
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

// ActiveOrHistoricCurrencyAnd13DecimalAmountSimpleType ...
type ActiveOrHistoricCurrencyAnd13DecimalAmountSimpleType float64

// ActiveOrHistoricCurrencyAnd13DecimalAmount ...
type ActiveOrHistoricCurrencyAnd13DecimalAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
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

// AmountAndCurrencyExchange3 ...
type AmountAndCurrencyExchange3 struct {
	InstdAmt      *AmountAndCurrencyExchangeDetails3   `xml:"InstdAmt"`
	TxAmt         *AmountAndCurrencyExchangeDetails3   `xml:"TxAmt"`
	CntrValAmt    *AmountAndCurrencyExchangeDetails3   `xml:"CntrValAmt"`
	AnncdPstngAmt *AmountAndCurrencyExchangeDetails3   `xml:"AnncdPstngAmt"`
	PrtryAmt      []*AmountAndCurrencyExchangeDetails4 `xml:"PrtryAmt"`
}

// AmountAndCurrencyExchangeDetails3 ...
type AmountAndCurrencyExchangeDetails3 struct {
	Amt     *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CcyXchg *CurrencyExchange5                 `xml:"CcyXchg"`
}

// AmountAndCurrencyExchangeDetails4 ...
type AmountAndCurrencyExchangeDetails4 struct {
	Tp      string                             `xml:"Tp"`
	Amt     *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CcyXchg *CurrencyExchange5                 `xml:"CcyXchg"`
}

// AmountAndDirection35 ...
type AmountAndDirection35 struct {
	Amt       float64 `xml:"Amt"`
	CdtDbtInd string  `xml:"CdtDbtInd"`
}

// AmountRangeBoundary1 ...
type AmountRangeBoundary1 struct {
	BdryAmt float64 `xml:"BdryAmt"`
	Incl    bool    `xml:"Incl"`
}

// AnyBICIdentifier ...
type AnyBICIdentifier string

// AttendanceContext1Code ...
type AttendanceContext1Code string

// AuthenticationEntity1Code ...
type AuthenticationEntity1Code string

// AuthenticationMethod1Code ...
type AuthenticationMethod1Code string

// BICFIIdentifier ...
type BICFIIdentifier string

// BalanceSubType1Choice ...
type BalanceSubType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// BalanceType12 ...
type BalanceType12 struct {
	CdOrPrtry *BalanceType5Choice    `xml:"CdOrPrtry"`
	SubTp     *BalanceSubType1Choice `xml:"SubTp"`
}

// BalanceType12Code ...
type BalanceType12Code string

// BalanceType5Choice ...
type BalanceType5Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// BankToCustomerStatementV05 ...
type BankToCustomerStatementV05 struct {
	GrpHdr      *GroupHeader58        `xml:"GrpHdr"`
	Stmt        []*AccountStatement5  `xml:"Stmt"`
	SplmtryData []*SupplementaryData1 `xml:"SplmtryData"`
}

// BankTransactionCodeStructure4 ...
type BankTransactionCodeStructure4 struct {
	Domn  *BankTransactionCodeStructure5            `xml:"Domn"`
	Prtry *ProprietaryBankTransactionCodeStructure1 `xml:"Prtry"`
}

// BankTransactionCodeStructure5 ...
type BankTransactionCodeStructure5 struct {
	Cd   string                         `xml:"Cd"`
	Fmly *BankTransactionCodeStructure6 `xml:"Fmly"`
}

// BankTransactionCodeStructure6 ...
type BankTransactionCodeStructure6 struct {
	Cd        string `xml:"Cd"`
	SubFmlyCd string `xml:"SubFmlyCd"`
}

// BaseOneRate ...
type BaseOneRate float64

// BatchInformation2 ...
type BatchInformation2 struct {
	MsgId     string                             `xml:"MsgId"`
	PmtInfId  string                             `xml:"PmtInfId"`
	NbOfTxs   string                             `xml:"NbOfTxs"`
	TtlAmt    *ActiveOrHistoricCurrencyAndAmount `xml:"TtlAmt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
}

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

// CSCManagement1Code ...
type CSCManagement1Code string

// CardAggregated1 ...
type CardAggregated1 struct {
	AddtlSvc      string                      `xml:"AddtlSvc"`
	TxCtgy        string                      `xml:"TxCtgy"`
	SaleRcncltnId string                      `xml:"SaleRcncltnId"`
	SeqNbRg       *CardSequenceNumberRange1   `xml:"SeqNbRg"`
	TxDtRg        *DateOrDateTimePeriodChoice `xml:"TxDtRg"`
}

// CardDataReading1Code ...
type CardDataReading1Code string

// CardEntry2 ...
type CardEntry2 struct {
	Card      *PaymentCard4        `xml:"Card"`
	POI       *PointOfInteraction1 `xml:"POI"`
	AggtdNtry *CardAggregated1     `xml:"AggtdNtry"`
	PrePdAcct *CashAccount24       `xml:"PrePdAcct"`
}

// CardIndividualTransaction2 ...
type CardIndividualTransaction2 struct {
	ICCRltdData    string                  `xml:"ICCRltdData"`
	PmtCntxt       *PaymentContext3        `xml:"PmtCntxt"`
	AddtlSvc       string                  `xml:"AddtlSvc"`
	TxCtgy         string                  `xml:"TxCtgy"`
	SaleRcncltnId  string                  `xml:"SaleRcncltnId"`
	SaleRefNb      string                  `xml:"SaleRefNb"`
	RePresntmntRsn string                  `xml:"RePresntmntRsn"`
	SeqNb          string                  `xml:"SeqNb"`
	TxId           *TransactionIdentifier1 `xml:"TxId"`
	Pdct           *Product2               `xml:"Pdct"`
	VldtnDt        string                  `xml:"VldtnDt"`
	VldtnSeqNb     string                  `xml:"VldtnSeqNb"`
}

// CardPaymentServiceType2Code ...
type CardPaymentServiceType2Code string

// CardSecurityInformation1 ...
type CardSecurityInformation1 struct {
	CSCMgmt string `xml:"CSCMgmt"`
	CSCVal  string `xml:"CSCVal"`
}

// CardSequenceNumberRange1 ...
type CardSequenceNumberRange1 struct {
	FrstTx string `xml:"FrstTx"`
	LastTx string `xml:"LastTx"`
}

// CardTransaction2 ...
type CardTransaction2 struct {
	Card      *PaymentCard4           `xml:"Card"`
	POI       *PointOfInteraction1    `xml:"POI"`
	Tx        *CardTransaction2Choice `xml:"Tx"`
	PrePdAcct *CashAccount24          `xml:"PrePdAcct"`
}

// CardTransaction2Choice ...
type CardTransaction2Choice struct {
	Aggtd *CardAggregated1            `xml:"Aggtd"`
	Indv  *CardIndividualTransaction2 `xml:"Indv"`
}

// CardholderAuthentication2 ...
type CardholderAuthentication2 struct {
	AuthntcnMtd  string `xml:"AuthntcnMtd"`
	AuthntcnNtty string `xml:"AuthntcnNtty"`
}

// CardholderVerificationCapability1Code ...
type CardholderVerificationCapability1Code string

// CashAccount24 ...
type CashAccount24 struct {
	Id  *AccountIdentification4Choice `xml:"Id"`
	Tp  *CashAccountType2Choice       `xml:"Tp"`
	Ccy string                        `xml:"Ccy"`
	Nm  string                        `xml:"Nm"`
}

// CashAccount25 ...
type CashAccount25 struct {
	Id   *AccountIdentification4Choice                 `xml:"Id"`
	Tp   *CashAccountType2Choice                       `xml:"Tp"`
	Ccy  string                                        `xml:"Ccy"`
	Nm   string                                        `xml:"Nm"`
	Ownr *PartyIdentification43                        `xml:"Ownr"`
	Svcr *BranchAndFinancialInstitutionIdentification5 `xml:"Svcr"`
}

// CashAccountType2Choice ...
type CashAccountType2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CashBalance3 ...
type CashBalance3 struct {
	Tp        *BalanceType12                     `xml:"Tp"`
	CdtLine   *CreditLine2                       `xml:"CdtLine"`
	Amt       *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Dt        *DateAndDateTimeChoice             `xml:"Dt"`
	Avlbty    []*CashBalanceAvailability2        `xml:"Avlbty"`
}

// CashBalanceAvailability2 ...
type CashBalanceAvailability2 struct {
	Dt        *CashBalanceAvailabilityDate1      `xml:"Dt"`
	Amt       *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
}

// CashBalanceAvailabilityDate1 ...
type CashBalanceAvailabilityDate1 struct {
	NbOfDays string `xml:"NbOfDays"`
	ActlDt   string `xml:"ActlDt"`
}

// CashDeposit1 ...
type CashDeposit1 struct {
	NoteDnmtn *ActiveCurrencyAndAmount `xml:"NoteDnmtn"`
	NbOfNotes string                   `xml:"NbOfNotes"`
	Amt       *ActiveCurrencyAndAmount `xml:"Amt"`
}

// ChargeBearerType1Code ...
type ChargeBearerType1Code string

// ChargeIncludedIndicator ...
type ChargeIncludedIndicator bool

// ChargeType3Choice ...
type ChargeType3Choice struct {
	Cd    string                  `xml:"Cd"`
	Prtry *GenericIdentification3 `xml:"Prtry"`
}

// Charges4 ...
type Charges4 struct {
	TtlChrgsAndTaxAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TtlChrgsAndTaxAmt"`
	Rcrd              []*ChargesRecord2                  `xml:"Rcrd"`
}

// ChargesRecord2 ...
type ChargesRecord2 struct {
	Amt         *ActiveOrHistoricCurrencyAndAmount            `xml:"Amt"`
	CdtDbtInd   string                                        `xml:"CdtDbtInd"`
	ChrgInclInd bool                                          `xml:"ChrgInclInd"`
	Tp          *ChargeType3Choice                            `xml:"Tp"`
	Rate        float64                                       `xml:"Rate"`
	Br          string                                        `xml:"Br"`
	Agt         *BranchAndFinancialInstitutionIdentification5 `xml:"Agt"`
	Tax         *TaxCharges2                                  `xml:"Tax"`
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

// CopyDuplicate1Code ...
type CopyDuplicate1Code string

// CorporateAction9 ...
type CorporateAction9 struct {
	EvtTp string `xml:"EvtTp"`
	EvtId string `xml:"EvtId"`
}

// CountryCode ...
type CountryCode string

// CreditDebitCode ...
type CreditDebitCode string

// CreditLine2 ...
type CreditLine2 struct {
	Incl bool                               `xml:"Incl"`
	Amt  *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
}

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

// CurrencyAndAmountRange2 ...
type CurrencyAndAmountRange2 struct {
	Amt       *ImpliedCurrencyAmountRangeChoice `xml:"Amt"`
	CdtDbtInd string                            `xml:"CdtDbtInd"`
	Ccy       string                            `xml:"Ccy"`
}

// CurrencyExchange5 ...
type CurrencyExchange5 struct {
	SrcCcy   string  `xml:"SrcCcy"`
	TrgtCcy  string  `xml:"TrgtCcy"`
	UnitCcy  string  `xml:"UnitCcy"`
	XchgRate float64 `xml:"XchgRate"`
	CtrctId  string  `xml:"CtrctId"`
	QtnDt    string  `xml:"QtnDt"`
}

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

// DateOrDateTimePeriodChoice ...
type DateOrDateTimePeriodChoice struct {
	Dt   *DatePeriodDetails     `xml:"Dt"`
	DtTm *DateTimePeriodDetails `xml:"DtTm"`
}

// DatePeriodDetails ...
type DatePeriodDetails struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// DateTimePeriodDetails ...
type DateTimePeriodDetails struct {
	FrDtTm string `xml:"FrDtTm"`
	ToDtTm string `xml:"ToDtTm"`
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

// DisplayCapabilities1 ...
type DisplayCapabilities1 struct {
	DispTp    string `xml:"DispTp"`
	NbOfLines string `xml:"NbOfLines"`
	LineWidth string `xml:"LineWidth"`
}

// DocumentAdjustment1 ...
type DocumentAdjustment1 struct {
	Amt       *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Rsn       string                             `xml:"Rsn"`
	AddtlInf  string                             `xml:"AddtlInf"`
}

// DocumentType3Code ...
type DocumentType3Code string

// DocumentType6Code ...
type DocumentType6Code string

// EntryDetails6 ...
type EntryDetails6 struct {
	Btch   *BatchInformation2   `xml:"Btch"`
	TxDtls []*EntryTransaction7 `xml:"TxDtls"`
}

// EntryStatus2Code ...
type EntryStatus2Code string

// EntryTransaction7 ...
type EntryTransaction7 struct {
	Refs        *TransactionReferences3            `xml:"Refs"`
	Amt         *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd   string                             `xml:"CdtDbtInd"`
	AmtDtls     *AmountAndCurrencyExchange3        `xml:"AmtDtls"`
	Avlbty      []*CashBalanceAvailability2        `xml:"Avlbty"`
	BkTxCd      *BankTransactionCodeStructure4     `xml:"BkTxCd"`
	Chrgs       *Charges4                          `xml:"Chrgs"`
	Intrst      *TransactionInterest3              `xml:"Intrst"`
	RltdPties   *TransactionParties3               `xml:"RltdPties"`
	RltdAgts    *TransactionAgents3                `xml:"RltdAgts"`
	Purp        *Purpose2Choice                    `xml:"Purp"`
	RltdRmtInf  []*RemittanceLocation4             `xml:"RltdRmtInf"`
	RmtInf      *RemittanceInformation10           `xml:"RmtInf"`
	RltdDts     *TransactionDates2                 `xml:"RltdDts"`
	RltdPric    *TransactionPrice3Choice           `xml:"RltdPric"`
	RltdQties   []*TransactionQuantities2Choice    `xml:"RltdQties"`
	FinInstrmId *SecurityIdentification14          `xml:"FinInstrmId"`
	Tax         *TaxInformation3                   `xml:"Tax"`
	RtrInf      *PaymentReturnReason2              `xml:"RtrInf"`
	CorpActn    *CorporateAction9                  `xml:"CorpActn"`
	SfkpgAcct   *SecuritiesAccount13               `xml:"SfkpgAcct"`
	CshDpst     []*CashDeposit1                    `xml:"CshDpst"`
	CardTx      *CardTransaction2                  `xml:"CardTx"`
	AddtlTxInf  string                             `xml:"AddtlTxInf"`
	SplmtryData []*SupplementaryData1              `xml:"SplmtryData"`
}

// Exact1NumericText ...
type Exact1NumericText string

// Exact3NumericText ...
type Exact3NumericText string

// Exact4AlphaNumericText ...
type Exact4AlphaNumericText string

// ExternalAccountIdentification1Code ...
type ExternalAccountIdentification1Code string

// ExternalBalanceSubType1Code ...
type ExternalBalanceSubType1Code string

// ExternalBankTransactionDomain1Code ...
type ExternalBankTransactionDomain1Code string

// ExternalBankTransactionFamily1Code ...
type ExternalBankTransactionFamily1Code string

// ExternalBankTransactionSubFamily1Code ...
type ExternalBankTransactionSubFamily1Code string

// ExternalCardTransactionCategory1Code ...
type ExternalCardTransactionCategory1Code string

// ExternalCashAccountType1Code ...
type ExternalCashAccountType1Code string

// ExternalChargeType1Code ...
type ExternalChargeType1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalDiscountAmountType1Code ...
type ExternalDiscountAmountType1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalFinancialInstrumentIdentificationType1Code ...
type ExternalFinancialInstrumentIdentificationType1Code string

// ExternalGarnishmentType1Code ...
type ExternalGarnishmentType1Code string

// ExternalOrganisationIdentification1Code ...
type ExternalOrganisationIdentification1Code string

// ExternalPersonIdentification1Code ...
type ExternalPersonIdentification1Code string

// ExternalPurpose1Code ...
type ExternalPurpose1Code string

// ExternalRePresentmentReason1Code ...
type ExternalRePresentmentReason1Code string

// ExternalReportingSource1Code ...
type ExternalReportingSource1Code string

// ExternalReturnReason1Code ...
type ExternalReturnReason1Code string

// ExternalTaxAmountType1Code ...
type ExternalTaxAmountType1Code string

// ExternalTechnicalInputChannel1Code ...
type ExternalTechnicalInputChannel1Code string

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

// FinancialInstrumentQuantityChoice ...
type FinancialInstrumentQuantityChoice struct {
	Unit     float64 `xml:"Unit"`
	FaceAmt  float64 `xml:"FaceAmt"`
	AmtsdVal float64 `xml:"AmtsdVal"`
}

// FromToAmountRange ...
type FromToAmountRange struct {
	FrAmt *AmountRangeBoundary1 `xml:"FrAmt"`
	ToAmt *AmountRangeBoundary1 `xml:"ToAmt"`
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

// GenericIdentification1 ...
type GenericIdentification1 struct {
	Id      string `xml:"Id"`
	SchmeNm string `xml:"SchmeNm"`
	Issr    string `xml:"Issr"`
}

// GenericIdentification20 ...
type GenericIdentification20 struct {
	Id      string `xml:"Id"`
	Issr    string `xml:"Issr"`
	SchmeNm string `xml:"SchmeNm"`
}

// GenericIdentification3 ...
type GenericIdentification3 struct {
	Id   string `xml:"Id"`
	Issr string `xml:"Issr"`
}

// GenericIdentification32 ...
type GenericIdentification32 struct {
	Id     string `xml:"Id"`
	Tp     string `xml:"Tp"`
	Issr   string `xml:"Issr"`
	ShrtNm string `xml:"ShrtNm"`
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

// GroupHeader58 ...
type GroupHeader58 struct {
	MsgId       string                  `xml:"MsgId"`
	CreDtTm     string                  `xml:"CreDtTm"`
	MsgRcpt     *PartyIdentification43  `xml:"MsgRcpt"`
	MsgPgntn    *Pagination             `xml:"MsgPgntn"`
	OrgnlBizQry *OriginalBusinessQuery1 `xml:"OrgnlBizQry"`
	AddtlInf    string                  `xml:"AddtlInf"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISINIdentifier ...
type ISINIdentifier string

// ISO2ALanguageCode ...
type ISO2ALanguageCode string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// ISOYearMonth ...
type ISOYearMonth string

// IdentificationSource3Choice ...
type IdentificationSource3Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ImpliedCurrencyAmountRangeChoice ...
type ImpliedCurrencyAmountRangeChoice struct {
	FrAmt   *AmountRangeBoundary1 `xml:"FrAmt"`
	ToAmt   *AmountRangeBoundary1 `xml:"ToAmt"`
	FrToAmt *FromToAmountRange    `xml:"FrToAmt"`
	EQAmt   float64               `xml:"EQAmt"`
	NEQAmt  float64               `xml:"NEQAmt"`
}

// ImpliedCurrencyAndAmount ...
type ImpliedCurrencyAndAmount float64

// InterestRecord1 ...
type InterestRecord1 struct {
	Amt       *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Tp        *InterestType1Choice               `xml:"Tp"`
	Rate      *Rate3                             `xml:"Rate"`
	FrToDt    *DateTimePeriodDetails             `xml:"FrToDt"`
	Rsn       string                             `xml:"Rsn"`
	Tax       *TaxCharges2                       `xml:"Tax"`
}

// InterestType1Choice ...
type InterestType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// InterestType1Code ...
type InterestType1Code string

// Max1025Text ...
type Max1025Text string

// Max105Text ...
type Max105Text string

// Max140Text ...
type Max140Text string

// Max15NumericText ...
type Max15NumericText string

// Max15PlusSignedNumericText ...
type Max15PlusSignedNumericText string

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

// Max3NumericText ...
type Max3NumericText string

// Max4Text ...
type Max4Text string

// Max500Text ...
type Max500Text string

// Max5NumericText ...
type Max5NumericText string

// Max70Text ...
type Max70Text string

// MessageIdentification2 ...
type MessageIdentification2 struct {
	MsgNmId string `xml:"MsgNmId"`
	MsgId   string `xml:"MsgId"`
}

// Min2Max3NumericText ...
type Min2Max3NumericText string

// Min3Max4NumericText ...
type Min3Max4NumericText string

// Min8Max28NumericText ...
type Min8Max28NumericText string

// NameAndAddress10 ...
type NameAndAddress10 struct {
	Nm  string          `xml:"Nm"`
	Adr *PostalAddress6 `xml:"Adr"`
}

// NamePrefix1Code ...
type NamePrefix1Code string

// NonNegativeDecimalNumber ...
type NonNegativeDecimalNumber float64

// Number ...
type Number float64

// NumberAndSumOfTransactions1 ...
type NumberAndSumOfTransactions1 struct {
	NbOfNtries string  `xml:"NbOfNtries"`
	Sum        float64 `xml:"Sum"`
}

// NumberAndSumOfTransactions4 ...
type NumberAndSumOfTransactions4 struct {
	NbOfNtries string                `xml:"NbOfNtries"`
	Sum        float64               `xml:"Sum"`
	TtlNetNtry *AmountAndDirection35 `xml:"TtlNetNtry"`
}

// OnLineCapability1Code ...
type OnLineCapability1Code string

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

// OriginalAndCurrentQuantities1 ...
type OriginalAndCurrentQuantities1 struct {
	FaceAmt  float64 `xml:"FaceAmt"`
	AmtsdVal float64 `xml:"AmtsdVal"`
}

// OriginalBusinessQuery1 ...
type OriginalBusinessQuery1 struct {
	MsgId   string `xml:"MsgId"`
	MsgNmId string `xml:"MsgNmId"`
	CreDtTm string `xml:"CreDtTm"`
}

// OtherIdentification1 ...
type OtherIdentification1 struct {
	Id  string                       `xml:"Id"`
	Sfx string                       `xml:"Sfx"`
	Tp  *IdentificationSource3Choice `xml:"Tp"`
}

// POIComponentType1Code ...
type POIComponentType1Code string

// Pagination ...
type Pagination struct {
	PgNb      string `xml:"PgNb"`
	LastPgInd bool   `xml:"LastPgInd"`
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

// PartyType3Code ...
type PartyType3Code string

// PartyType4Code ...
type PartyType4Code string

// PaymentCard4 ...
type PaymentCard4 struct {
	PlainCardData *PlainCardData1         `xml:"PlainCardData"`
	CardCtryCd    string                  `xml:"CardCtryCd"`
	CardBrnd      *GenericIdentification1 `xml:"CardBrnd"`
	AddtlCardData string                  `xml:"AddtlCardData"`
}

// PaymentContext3 ...
type PaymentContext3 struct {
	CardPres       bool                       `xml:"CardPres"`
	CrdhldrPres    bool                       `xml:"CrdhldrPres"`
	OnLineCntxt    bool                       `xml:"OnLineCntxt"`
	AttndncCntxt   string                     `xml:"AttndncCntxt"`
	TxEnvt         string                     `xml:"TxEnvt"`
	TxChanl        string                     `xml:"TxChanl"`
	AttndntMsgCpbl bool                       `xml:"AttndntMsgCpbl"`
	AttndntLang    string                     `xml:"AttndntLang"`
	CardDataNtryMd string                     `xml:"CardDataNtryMd"`
	FllbckInd      bool                       `xml:"FllbckInd"`
	AuthntcnMtd    *CardholderAuthentication2 `xml:"AuthntcnMtd"`
}

// PaymentReturnReason2 ...
type PaymentReturnReason2 struct {
	OrgnlBkTxCd *BankTransactionCodeStructure4 `xml:"OrgnlBkTxCd"`
	Orgtr       *PartyIdentification43         `xml:"Orgtr"`
	Rsn         *ReturnReason5Choice           `xml:"Rsn"`
	AddtlInf    []string                       `xml:"AddtlInf"`
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

// PlainCardData1 ...
type PlainCardData1 struct {
	PAN        string                    `xml:"PAN"`
	CardSeqNb  string                    `xml:"CardSeqNb"`
	FctvDt     string                    `xml:"FctvDt"`
	XpryDt     string                    `xml:"XpryDt"`
	SvcCd      string                    `xml:"SvcCd"`
	TrckData   []*TrackData1             `xml:"TrckData"`
	CardSctyCd *CardSecurityInformation1 `xml:"CardSctyCd"`
}

// PointOfInteraction1 ...
type PointOfInteraction1 struct {
	Id       *GenericIdentification32         `xml:"Id"`
	SysNm    string                           `xml:"SysNm"`
	GrpId    string                           `xml:"GrpId"`
	Cpblties *PointOfInteractionCapabilities1 `xml:"Cpblties"`
	Cmpnt    []*PointOfInteractionComponent1  `xml:"Cmpnt"`
}

// PointOfInteractionCapabilities1 ...
type PointOfInteractionCapabilities1 struct {
	CardRdngCpblties      []string                `xml:"CardRdngCpblties"`
	CrdhldrVrfctnCpblties []string                `xml:"CrdhldrVrfctnCpblties"`
	OnLineCpblties        string                  `xml:"OnLineCpblties"`
	DispCpblties          []*DisplayCapabilities1 `xml:"DispCpblties"`
	PrtLineWidth          string                  `xml:"PrtLineWidth"`
}

// PointOfInteractionComponent1 ...
type PointOfInteractionComponent1 struct {
	POICmpntTp string   `xml:"POICmpntTp"`
	ManfctrId  string   `xml:"ManfctrId"`
	Mdl        string   `xml:"Mdl"`
	VrsnNb     string   `xml:"VrsnNb"`
	SrlNb      string   `xml:"SrlNb"`
	ApprvlNb   []string `xml:"ApprvlNb"`
}

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

// Price2 ...
type Price2 struct {
	Tp  *YieldedOrValueType1Choice `xml:"Tp"`
	Val *PriceRateOrAmountChoice   `xml:"Val"`
}

// PriceRateOrAmountChoice ...
type PriceRateOrAmountChoice struct {
	Rate float64                                     `xml:"Rate"`
	Amt  *ActiveOrHistoricCurrencyAnd13DecimalAmount `xml:"Amt"`
}

// PriceValueType1Code ...
type PriceValueType1Code string

// Product2 ...
type Product2 struct {
	PdctCd       string  `xml:"PdctCd"`
	UnitOfMeasr  string  `xml:"UnitOfMeasr"`
	PdctQty      float64 `xml:"PdctQty"`
	UnitPric     float64 `xml:"UnitPric"`
	PdctAmt      float64 `xml:"PdctAmt"`
	TaxTp        string  `xml:"TaxTp"`
	AddtlPdctInf string  `xml:"AddtlPdctInf"`
}

// ProprietaryAgent3 ...
type ProprietaryAgent3 struct {
	Tp  string                                        `xml:"Tp"`
	Agt *BranchAndFinancialInstitutionIdentification5 `xml:"Agt"`
}

// ProprietaryBankTransactionCodeStructure1 ...
type ProprietaryBankTransactionCodeStructure1 struct {
	Cd   string `xml:"Cd"`
	Issr string `xml:"Issr"`
}

// ProprietaryDate2 ...
type ProprietaryDate2 struct {
	Tp string                 `xml:"Tp"`
	Dt *DateAndDateTimeChoice `xml:"Dt"`
}

// ProprietaryParty3 ...
type ProprietaryParty3 struct {
	Tp  string                 `xml:"Tp"`
	Pty *PartyIdentification43 `xml:"Pty"`
}

// ProprietaryPrice2 ...
type ProprietaryPrice2 struct {
	Tp   string                             `xml:"Tp"`
	Pric *ActiveOrHistoricCurrencyAndAmount `xml:"Pric"`
}

// ProprietaryQuantity1 ...
type ProprietaryQuantity1 struct {
	Tp  string `xml:"Tp"`
	Qty string `xml:"Qty"`
}

// ProprietaryReference1 ...
type ProprietaryReference1 struct {
	Tp  string `xml:"Tp"`
	Ref string `xml:"Ref"`
}

// Purpose2Choice ...
type Purpose2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// Rate3 ...
type Rate3 struct {
	Tp      *RateType4Choice         `xml:"Tp"`
	VldtyRg *CurrencyAndAmountRange2 `xml:"VldtyRg"`
}

// RateType4Choice ...
type RateType4Choice struct {
	Pctg float64 `xml:"Pctg"`
	Othr string  `xml:"Othr"`
}

// ReferredDocumentInformation6 ...
type ReferredDocumentInformation6 struct {
	Tp     *ReferredDocumentType4 `xml:"Tp"`
	Nb     string                 `xml:"Nb"`
	RltdDt string                 `xml:"RltdDt"`
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

// RemittanceInformation10 ...
type RemittanceInformation10 struct {
	Ustrd []string                             `xml:"Ustrd"`
	Strd  []*StructuredRemittanceInformation12 `xml:"Strd"`
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

// ReportEntry7 ...
type ReportEntry7 struct {
	NtryRef       string                             `xml:"NtryRef"`
	Amt           *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd     string                             `xml:"CdtDbtInd"`
	RvslInd       bool                               `xml:"RvslInd"`
	Sts           string                             `xml:"Sts"`
	BookgDt       *DateAndDateTimeChoice             `xml:"BookgDt"`
	ValDt         *DateAndDateTimeChoice             `xml:"ValDt"`
	AcctSvcrRef   string                             `xml:"AcctSvcrRef"`
	Avlbty        []*CashBalanceAvailability2        `xml:"Avlbty"`
	BkTxCd        *BankTransactionCodeStructure4     `xml:"BkTxCd"`
	ComssnWvrInd  bool                               `xml:"ComssnWvrInd"`
	AddtlInfInd   *MessageIdentification2            `xml:"AddtlInfInd"`
	AmtDtls       *AmountAndCurrencyExchange3        `xml:"AmtDtls"`
	Chrgs         *Charges4                          `xml:"Chrgs"`
	TechInptChanl *TechnicalInputChannel1Choice      `xml:"TechInptChanl"`
	Intrst        *TransactionInterest3              `xml:"Intrst"`
	CardTx        *CardEntry2                        `xml:"CardTx"`
	NtryDtls      []*EntryDetails6                   `xml:"NtryDtls"`
	AddtlNtryInf  string                             `xml:"AddtlNtryInf"`
}

// ReportingSource1Choice ...
type ReportingSource1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ReturnReason5Choice ...
type ReturnReason5Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// SecuritiesAccount13 ...
type SecuritiesAccount13 struct {
	Id string                   `xml:"Id"`
	Tp *GenericIdentification20 `xml:"Tp"`
	Nm string                   `xml:"Nm"`
}

// SecurityIdentification14 ...
type SecurityIdentification14 struct {
	ISIN   string                  `xml:"ISIN"`
	OthrId []*OtherIdentification1 `xml:"OthrId"`
	Desc   string                  `xml:"Desc"`
}

// StructuredRemittanceInformation12 ...
type StructuredRemittanceInformation12 struct {
	RfrdDocInf  []*ReferredDocumentInformation6 `xml:"RfrdDocInf"`
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

// TaxInformation3 ...
type TaxInformation3 struct {
	Cdtr            *TaxParty1                         `xml:"Cdtr"`
	Dbtr            *TaxParty2                         `xml:"Dbtr"`
	AdmstnZn        string                             `xml:"AdmstnZn"`
	RefNb           string                             `xml:"RefNb"`
	Mtd             string                             `xml:"Mtd"`
	TtlTaxblBaseAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TtlTaxblBaseAmt"`
	TtlTaxAmt       *ActiveOrHistoricCurrencyAndAmount `xml:"TtlTaxAmt"`
	Dt              string                             `xml:"Dt"`
	SeqNb           float64                            `xml:"SeqNb"`
	Rcrd            []*TaxRecord1                      `xml:"Rcrd"`
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

// TechnicalInputChannel1Choice ...
type TechnicalInputChannel1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// TotalTransactions4 ...
type TotalTransactions4 struct {
	TtlNtries          *NumberAndSumOfTransactions4     `xml:"TtlNtries"`
	TtlCdtNtries       *NumberAndSumOfTransactions1     `xml:"TtlCdtNtries"`
	TtlDbtNtries       *NumberAndSumOfTransactions1     `xml:"TtlDbtNtries"`
	TtlNtriesPerBkTxCd []*TotalsPerBankTransactionCode3 `xml:"TtlNtriesPerBkTxCd"`
}

// TotalsPerBankTransactionCode3 ...
type TotalsPerBankTransactionCode3 struct {
	NbOfNtries string                         `xml:"NbOfNtries"`
	Sum        float64                        `xml:"Sum"`
	TtlNetNtry *AmountAndDirection35          `xml:"TtlNetNtry"`
	FcstInd    bool                           `xml:"FcstInd"`
	BkTxCd     *BankTransactionCodeStructure4 `xml:"BkTxCd"`
	Avlbty     []*CashBalanceAvailability2    `xml:"Avlbty"`
}

// TrackData1 ...
type TrackData1 struct {
	TrckNb  string `xml:"TrckNb"`
	TrckVal string `xml:"TrckVal"`
}

// TransactionAgents3 ...
type TransactionAgents3 struct {
	DbtrAgt    *BranchAndFinancialInstitutionIdentification5 `xml:"DbtrAgt"`
	CdtrAgt    *BranchAndFinancialInstitutionIdentification5 `xml:"CdtrAgt"`
	IntrmyAgt1 *BranchAndFinancialInstitutionIdentification5 `xml:"IntrmyAgt1"`
	IntrmyAgt2 *BranchAndFinancialInstitutionIdentification5 `xml:"IntrmyAgt2"`
	IntrmyAgt3 *BranchAndFinancialInstitutionIdentification5 `xml:"IntrmyAgt3"`
	RcvgAgt    *BranchAndFinancialInstitutionIdentification5 `xml:"RcvgAgt"`
	DlvrgAgt   *BranchAndFinancialInstitutionIdentification5 `xml:"DlvrgAgt"`
	IssgAgt    *BranchAndFinancialInstitutionIdentification5 `xml:"IssgAgt"`
	SttlmPlc   *BranchAndFinancialInstitutionIdentification5 `xml:"SttlmPlc"`
	Prtry      []*ProprietaryAgent3                          `xml:"Prtry"`
}

// TransactionChannel1Code ...
type TransactionChannel1Code string

// TransactionDates2 ...
type TransactionDates2 struct {
	AccptncDtTm             string              `xml:"AccptncDtTm"`
	TradActvtyCtrctlSttlmDt string              `xml:"TradActvtyCtrctlSttlmDt"`
	TradDt                  string              `xml:"TradDt"`
	IntrBkSttlmDt           string              `xml:"IntrBkSttlmDt"`
	StartDt                 string              `xml:"StartDt"`
	EndDt                   string              `xml:"EndDt"`
	TxDtTm                  string              `xml:"TxDtTm"`
	Prtry                   []*ProprietaryDate2 `xml:"Prtry"`
}

// TransactionEnvironment1Code ...
type TransactionEnvironment1Code string

// TransactionIdentifier1 ...
type TransactionIdentifier1 struct {
	TxDtTm string `xml:"TxDtTm"`
	TxRef  string `xml:"TxRef"`
}

// TransactionInterest3 ...
type TransactionInterest3 struct {
	TtlIntrstAndTaxAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TtlIntrstAndTaxAmt"`
	Rcrd               []*InterestRecord1                 `xml:"Rcrd"`
}

// TransactionParties3 ...
type TransactionParties3 struct {
	InitgPty  *PartyIdentification43 `xml:"InitgPty"`
	Dbtr      *PartyIdentification43 `xml:"Dbtr"`
	DbtrAcct  *CashAccount24         `xml:"DbtrAcct"`
	UltmtDbtr *PartyIdentification43 `xml:"UltmtDbtr"`
	Cdtr      *PartyIdentification43 `xml:"Cdtr"`
	CdtrAcct  *CashAccount24         `xml:"CdtrAcct"`
	UltmtCdtr *PartyIdentification43 `xml:"UltmtCdtr"`
	TradgPty  *PartyIdentification43 `xml:"TradgPty"`
	Prtry     []*ProprietaryParty3   `xml:"Prtry"`
}

// TransactionPrice3Choice ...
type TransactionPrice3Choice struct {
	DealPric *Price2              `xml:"DealPric"`
	Prtry    []*ProprietaryPrice2 `xml:"Prtry"`
}

// TransactionQuantities2Choice ...
type TransactionQuantities2Choice struct {
	Qty                *FinancialInstrumentQuantityChoice `xml:"Qty"`
	OrgnlAndCurFaceAmt *OriginalAndCurrentQuantities1     `xml:"OrgnlAndCurFaceAmt"`
	Prtry              *ProprietaryQuantity1              `xml:"Prtry"`
}

// TransactionReferences3 ...
type TransactionReferences3 struct {
	MsgId             string                   `xml:"MsgId"`
	AcctSvcrRef       string                   `xml:"AcctSvcrRef"`
	PmtInfId          string                   `xml:"PmtInfId"`
	InstrId           string                   `xml:"InstrId"`
	EndToEndId        string                   `xml:"EndToEndId"`
	TxId              string                   `xml:"TxId"`
	MndtId            string                   `xml:"MndtId"`
	ChqNb             string                   `xml:"ChqNb"`
	ClrSysRef         string                   `xml:"ClrSysRef"`
	AcctOwnrTxId      string                   `xml:"AcctOwnrTxId"`
	AcctSvcrTxId      string                   `xml:"AcctSvcrTxId"`
	MktInfrstrctrTxId string                   `xml:"MktInfrstrctrTxId"`
	PrcgId            string                   `xml:"PrcgId"`
	Prtry             []*ProprietaryReference1 `xml:"Prtry"`
}

// TrueFalseIndicator ...
type TrueFalseIndicator bool

// UnitOfMeasure1Code ...
type UnitOfMeasure1Code string

// UserInterface2Code ...
type UserInterface2Code string

// YesNoIndicator ...
type YesNoIndicator bool

// YieldedOrValueType1Choice ...
type YieldedOrValueType1Choice struct {
	Yldd  bool   `xml:"Yldd"`
	ValTp string `xml:"ValTp"`
}
