package schema

// Document ...
type Document *Document

// AccountIdentification4Choice ...
type AccountIdentification4Choice struct {
	IBAN string                         `xml:"IBAN"`
	Othr *GenericAccountIdentification1 `xml:"Othr"`
}

// AccountInterest4 ...
type AccountInterest4 struct {
	Tp     *InterestType1Choice `xml:"Tp"`
	Rate   []*Rate4             `xml:"Rate"`
	FrToDt *DateTimePeriod1     `xml:"FrToDt"`
	Rsn    string               `xml:"Rsn"`
	Tax    *TaxCharges2         `xml:"Tax"`
}

// AccountNotification15 ...
type AccountNotification15 struct {
	Id             string                  `xml:"Id"`
	NtfctnPgntn    *Pagination1            `xml:"NtfctnPgntn"`
	ElctrncSeqNb   float64                 `xml:"ElctrncSeqNb"`
	RptgSeq        *SequenceRange1Choice   `xml:"RptgSeq"`
	LglSeqNb       float64                 `xml:"LglSeqNb"`
	CreDtTm        string                  `xml:"CreDtTm"`
	FrToDt         *DateTimePeriod1        `xml:"FrToDt"`
	CpyDplctInd    string                  `xml:"CpyDplctInd"`
	RptgSrc        *ReportingSource1Choice `xml:"RptgSrc"`
	Acct           *CashAccount36          `xml:"Acct"`
	RltdAcct       *CashAccount24          `xml:"RltdAcct"`
	Intrst         []*AccountInterest4     `xml:"Intrst"`
	TxsSummry      *TotalTransactions6     `xml:"TxsSummry"`
	Ntry           []*ReportEntry9         `xml:"Ntry"`
	AddtlNtfctnInf string                  `xml:"AddtlNtfctnInf"`
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

// ActiveOrHistoricCurrencyAndAmountRange2 ...
type ActiveOrHistoricCurrencyAndAmountRange2 struct {
	Amt       *ImpliedCurrencyAmountRange1Choice `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Ccy       string                             `xml:"Ccy"`
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

// BankToCustomerDebitCreditNotificationV07 ...
type BankToCustomerDebitCreditNotificationV07 struct {
	GrpHdr      *GroupHeader73           `xml:"GrpHdr"`
	Ntfctn      []*AccountNotification15 `xml:"Ntfctn"`
	SplmtryData []*SupplementaryData1    `xml:"SplmtryData"`
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

// CardAggregated2 ...
type CardAggregated2 struct {
	AddtlSvc      string                       `xml:"AddtlSvc"`
	TxCtgy        string                       `xml:"TxCtgy"`
	SaleRcncltnId string                       `xml:"SaleRcncltnId"`
	SeqNbRg       *CardSequenceNumberRange1    `xml:"SeqNbRg"`
	TxDtRg        *DateOrDateTimePeriod1Choice `xml:"TxDtRg"`
}

// CardDataReading1Code ...
type CardDataReading1Code string

// CardEntry3 ...
type CardEntry3 struct {
	Card      *PaymentCard4        `xml:"Card"`
	POI       *PointOfInteraction1 `xml:"POI"`
	AggtdNtry *CardAggregated2     `xml:"AggtdNtry"`
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

// CardTransaction16 ...
type CardTransaction16 struct {
	Card      *PaymentCard4           `xml:"Card"`
	POI       *PointOfInteraction1    `xml:"POI"`
	Tx        *CardTransaction3Choice `xml:"Tx"`
	PrePdAcct *CashAccount24          `xml:"PrePdAcct"`
}

// CardTransaction3Choice ...
type CardTransaction3Choice struct {
	Aggtd *CardAggregated2            `xml:"Aggtd"`
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

// CashAccount36 ...
type CashAccount36 struct {
	Id   *AccountIdentification4Choice                 `xml:"Id"`
	Tp   *CashAccountType2Choice                       `xml:"Tp"`
	Ccy  string                                        `xml:"Ccy"`
	Nm   string                                        `xml:"Nm"`
	Ownr *PartyIdentification125                       `xml:"Ownr"`
	Svcr *BranchAndFinancialInstitutionIdentification5 `xml:"Svcr"`
}

// CashAccountType2Choice ...
type CashAccountType2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// CashAvailability1 ...
type CashAvailability1 struct {
	Dt        *CashAvailabilityDate1Choice       `xml:"Dt"`
	Amt       *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
}

// CashAvailabilityDate1Choice ...
type CashAvailabilityDate1Choice struct {
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

// CurrencyExchange5 ...
type CurrencyExchange5 struct {
	SrcCcy   string  `xml:"SrcCcy"`
	TrgtCcy  string  `xml:"TrgtCcy"`
	UnitCcy  string  `xml:"UnitCcy"`
	XchgRate float64 `xml:"XchgRate"`
	CtrctId  string  `xml:"CtrctId"`
	QtnDt    string  `xml:"QtnDt"`
}

// DateAndDateTime2Choice ...
type DateAndDateTime2Choice struct {
	Dt   string `xml:"Dt"`
	DtTm string `xml:"DtTm"`
}

// DateAndPlaceOfBirth1 ...
type DateAndPlaceOfBirth1 struct {
	BirthDt     string `xml:"BirthDt"`
	PrvcOfBirth string `xml:"PrvcOfBirth"`
	CityOfBirth string `xml:"CityOfBirth"`
	CtryOfBirth string `xml:"CtryOfBirth"`
}

// DateOrDateTimePeriod1Choice ...
type DateOrDateTimePeriod1Choice struct {
	Dt   *DatePeriod2     `xml:"Dt"`
	DtTm *DateTimePeriod1 `xml:"DtTm"`
}

// DatePeriod2 ...
type DatePeriod2 struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// DateTimePeriod1 ...
type DateTimePeriod1 struct {
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

// EntryDetails8 ...
type EntryDetails8 struct {
	Btch   *BatchInformation2   `xml:"Btch"`
	TxDtls []*EntryTransaction9 `xml:"TxDtls"`
}

// EntryStatus1Choice ...
type EntryStatus1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// EntryTransaction9 ...
type EntryTransaction9 struct {
	Refs        *TransactionReferences3            `xml:"Refs"`
	Amt         *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd   string                             `xml:"CdtDbtInd"`
	AmtDtls     *AmountAndCurrencyExchange3        `xml:"AmtDtls"`
	Avlbty      []*CashAvailability1               `xml:"Avlbty"`
	BkTxCd      *BankTransactionCodeStructure4     `xml:"BkTxCd"`
	Chrgs       *Charges4                          `xml:"Chrgs"`
	Intrst      *TransactionInterest4              `xml:"Intrst"`
	RltdPties   *TransactionParties4               `xml:"RltdPties"`
	RltdAgts    *TransactionAgents4                `xml:"RltdAgts"`
	LclInstrm   *LocalInstrument2Choice            `xml:"LclInstrm"`
	Purp        *Purpose2Choice                    `xml:"Purp"`
	RltdRmtInf  []*RemittanceLocation4             `xml:"RltdRmtInf"`
	RmtInf      *RemittanceInformation15           `xml:"RmtInf"`
	RltdDts     *TransactionDates3                 `xml:"RltdDts"`
	RltdPric    *TransactionPrice4Choice           `xml:"RltdPric"`
	RltdQties   []*TransactionQuantities2Choice    `xml:"RltdQties"`
	FinInstrmId *SecurityIdentification19          `xml:"FinInstrmId"`
	Tax         *TaxInformation6                   `xml:"Tax"`
	RtrInf      *PaymentReturnReason3              `xml:"RtrInf"`
	CorpActn    *CorporateAction9                  `xml:"CorpActn"`
	SfkpgAcct   *SecuritiesAccount19               `xml:"SfkpgAcct"`
	CshDpst     []*CashDeposit1                    `xml:"CshDpst"`
	CardTx      *CardTransaction16                 `xml:"CardTx"`
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

// ExternalDocumentLineType1Code ...
type ExternalDocumentLineType1Code string

// ExternalEntryStatus1Code ...
type ExternalEntryStatus1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalFinancialInstrumentIdentificationType1Code ...
type ExternalFinancialInstrumentIdentificationType1Code string

// ExternalGarnishmentType1Code ...
type ExternalGarnishmentType1Code string

// ExternalLocalInstrument1Code ...
type ExternalLocalInstrument1Code string

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

// FromToAmountRange1 ...
type FromToAmountRange1 struct {
	FrAmt *AmountRangeBoundary1 `xml:"FrAmt"`
	ToAmt *AmountRangeBoundary1 `xml:"ToAmt"`
}

// Garnishment2 ...
type Garnishment2 struct {
	Tp                *GarnishmentType1                  `xml:"Tp"`
	Grnshee           *PartyIdentification125            `xml:"Grnshee"`
	GrnshmtAdmstr     *PartyIdentification125            `xml:"GrnshmtAdmstr"`
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

// GenericIdentification3 ...
type GenericIdentification3 struct {
	Id   string `xml:"Id"`
	Issr string `xml:"Issr"`
}

// GenericIdentification30 ...
type GenericIdentification30 struct {
	Id      string `xml:"Id"`
	Issr    string `xml:"Issr"`
	SchmeNm string `xml:"SchmeNm"`
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

// GroupHeader73 ...
type GroupHeader73 struct {
	MsgId       string                  `xml:"MsgId"`
	CreDtTm     string                  `xml:"CreDtTm"`
	MsgRcpt     *PartyIdentification125 `xml:"MsgRcpt"`
	MsgPgntn    *Pagination1            `xml:"MsgPgntn"`
	OrgnlBizQry *OriginalBusinessQuery1 `xml:"OrgnlBizQry"`
	AddtlInf    string                  `xml:"AddtlInf"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISINOct2015Identifier ...
type ISINOct2015Identifier string

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

// ImpliedCurrencyAmountRange1Choice ...
type ImpliedCurrencyAmountRange1Choice struct {
	FrAmt   *AmountRangeBoundary1 `xml:"FrAmt"`
	ToAmt   *AmountRangeBoundary1 `xml:"ToAmt"`
	FrToAmt *FromToAmountRange1   `xml:"FrToAmt"`
	EQAmt   float64               `xml:"EQAmt"`
	NEQAmt  float64               `xml:"NEQAmt"`
}

// ImpliedCurrencyAndAmount ...
type ImpliedCurrencyAndAmount float64

// InterestRecord2 ...
type InterestRecord2 struct {
	Amt       *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd string                             `xml:"CdtDbtInd"`
	Tp        *InterestType1Choice               `xml:"Tp"`
	Rate      *Rate4                             `xml:"Rate"`
	FrToDt    *DateTimePeriod1                   `xml:"FrToDt"`
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

// LocalInstrument2Choice ...
type LocalInstrument2Choice struct {
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

// Pagination1 ...
type Pagination1 struct {
	PgNb      string `xml:"PgNb"`
	LastPgInd bool   `xml:"LastPgInd"`
}

// Party34Choice ...
type Party34Choice struct {
	OrgId  *OrganisationIdentification8 `xml:"OrgId"`
	PrvtId *PersonIdentification13      `xml:"PrvtId"`
}

// Party35Choice ...
type Party35Choice struct {
	Pty *PartyIdentification125                       `xml:"Pty"`
	Agt *BranchAndFinancialInstitutionIdentification5 `xml:"Agt"`
}

// PartyIdentification125 ...
type PartyIdentification125 struct {
	Nm        string           `xml:"Nm"`
	PstlAdr   *PostalAddress6  `xml:"PstlAdr"`
	Id        *Party34Choice   `xml:"Id"`
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

// PaymentReturnReason3 ...
type PaymentReturnReason3 struct {
	OrgnlBkTxCd *BankTransactionCodeStructure4 `xml:"OrgnlBkTxCd"`
	Orgtr       *PartyIdentification125        `xml:"Orgtr"`
	Rsn         *ReturnReason5Choice           `xml:"Rsn"`
	AddtlInf    []string                       `xml:"AddtlInf"`
}

// PercentageRate ...
type PercentageRate float64

// PersonIdentification13 ...
type PersonIdentification13 struct {
	DtAndPlcOfBirth *DateAndPlaceOfBirth1           `xml:"DtAndPlcOfBirth"`
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

// Price7 ...
type Price7 struct {
	Tp  *YieldedOrValueType1Choice `xml:"Tp"`
	Val *PriceRateOrAmount3Choice  `xml:"Val"`
}

// PriceRateOrAmount3Choice ...
type PriceRateOrAmount3Choice struct {
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

// ProprietaryDate3 ...
type ProprietaryDate3 struct {
	Tp string                  `xml:"Tp"`
	Dt *DateAndDateTime2Choice `xml:"Dt"`
}

// ProprietaryParty4 ...
type ProprietaryParty4 struct {
	Tp  string         `xml:"Tp"`
	Pty *Party35Choice `xml:"Pty"`
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

// Rate4 ...
type Rate4 struct {
	Tp      *RateType4Choice                         `xml:"Tp"`
	VldtyRg *ActiveOrHistoricCurrencyAndAmountRange2 `xml:"VldtyRg"`
}

// RateType4Choice ...
type RateType4Choice struct {
	Pctg float64 `xml:"Pctg"`
	Othr string  `xml:"Othr"`
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

// RemittanceInformation15 ...
type RemittanceInformation15 struct {
	Ustrd []string                             `xml:"Ustrd"`
	Strd  []*StructuredRemittanceInformation15 `xml:"Strd"`
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

// ReportEntry9 ...
type ReportEntry9 struct {
	NtryRef       string                             `xml:"NtryRef"`
	Amt           *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	CdtDbtInd     string                             `xml:"CdtDbtInd"`
	RvslInd       bool                               `xml:"RvslInd"`
	Sts           *EntryStatus1Choice                `xml:"Sts"`
	BookgDt       *DateAndDateTime2Choice            `xml:"BookgDt"`
	ValDt         *DateAndDateTime2Choice            `xml:"ValDt"`
	AcctSvcrRef   string                             `xml:"AcctSvcrRef"`
	Avlbty        []*CashAvailability1               `xml:"Avlbty"`
	BkTxCd        *BankTransactionCodeStructure4     `xml:"BkTxCd"`
	ComssnWvrInd  bool                               `xml:"ComssnWvrInd"`
	AddtlInfInd   *MessageIdentification2            `xml:"AddtlInfInd"`
	AmtDtls       *AmountAndCurrencyExchange3        `xml:"AmtDtls"`
	Chrgs         *Charges4                          `xml:"Chrgs"`
	TechInptChanl *TechnicalInputChannel1Choice      `xml:"TechInptChanl"`
	Intrst        *TransactionInterest4              `xml:"Intrst"`
	CardTx        *CardEntry3                        `xml:"CardTx"`
	NtryDtls      []*EntryDetails8                   `xml:"NtryDtls"`
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

// SecuritiesAccount19 ...
type SecuritiesAccount19 struct {
	Id string                   `xml:"Id"`
	Tp *GenericIdentification30 `xml:"Tp"`
	Nm string                   `xml:"Nm"`
}

// SecurityIdentification19 ...
type SecurityIdentification19 struct {
	ISIN   string                  `xml:"ISIN"`
	OthrId []*OtherIdentification1 `xml:"OthrId"`
	Desc   string                  `xml:"Desc"`
}

// SequenceRange1 ...
type SequenceRange1 struct {
	FrSeq string `xml:"FrSeq"`
	ToSeq string `xml:"ToSeq"`
}

// SequenceRange1Choice ...
type SequenceRange1Choice struct {
	FrSeq   string            `xml:"FrSeq"`
	ToSeq   string            `xml:"ToSeq"`
	FrToSeq []*SequenceRange1 `xml:"FrToSeq"`
	EQSeq   []string          `xml:"EQSeq"`
	NEQSeq  []string          `xml:"NEQSeq"`
}

// StructuredRemittanceInformation15 ...
type StructuredRemittanceInformation15 struct {
	RfrdDocInf  []*ReferredDocumentInformation7 `xml:"RfrdDocInf"`
	RfrdDocAmt  *RemittanceAmount2              `xml:"RfrdDocAmt"`
	CdtrRefInf  *CreditorReferenceInformation2  `xml:"CdtrRefInf"`
	Invcr       *PartyIdentification125         `xml:"Invcr"`
	Invcee      *PartyIdentification125         `xml:"Invcee"`
	TaxRmt      *TaxInformation7                `xml:"TaxRmt"`
	GrnshmtRmt  *Garnishment2                   `xml:"GrnshmtRmt"`
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

// TaxAmount2 ...
type TaxAmount2 struct {
	Rate         float64                            `xml:"Rate"`
	TaxblBaseAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TaxblBaseAmt"`
	TtlAmt       *ActiveOrHistoricCurrencyAndAmount `xml:"TtlAmt"`
	Dtls         []*TaxRecordDetails2               `xml:"Dtls"`
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

// TaxInformation6 ...
type TaxInformation6 struct {
	Cdtr            *TaxParty1                         `xml:"Cdtr"`
	Dbtr            *TaxParty2                         `xml:"Dbtr"`
	AdmstnZn        string                             `xml:"AdmstnZn"`
	RefNb           string                             `xml:"RefNb"`
	Mtd             string                             `xml:"Mtd"`
	TtlTaxblBaseAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TtlTaxblBaseAmt"`
	TtlTaxAmt       *ActiveOrHistoricCurrencyAndAmount `xml:"TtlTaxAmt"`
	Dt              string                             `xml:"Dt"`
	SeqNb           float64                            `xml:"SeqNb"`
	Rcrd            []*TaxRecord2                      `xml:"Rcrd"`
}

// TaxInformation7 ...
type TaxInformation7 struct {
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
	Rcrd            []*TaxRecord2                      `xml:"Rcrd"`
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

// TaxPeriod2 ...
type TaxPeriod2 struct {
	Yr     string       `xml:"Yr"`
	Tp     string       `xml:"Tp"`
	FrToDt *DatePeriod2 `xml:"FrToDt"`
}

// TaxRecord2 ...
type TaxRecord2 struct {
	Tp       string      `xml:"Tp"`
	Ctgy     string      `xml:"Ctgy"`
	CtgyDtls string      `xml:"CtgyDtls"`
	DbtrSts  string      `xml:"DbtrSts"`
	CertId   string      `xml:"CertId"`
	FrmsCd   string      `xml:"FrmsCd"`
	Prd      *TaxPeriod2 `xml:"Prd"`
	TaxAmt   *TaxAmount2 `xml:"TaxAmt"`
	AddtlInf string      `xml:"AddtlInf"`
}

// TaxRecordDetails2 ...
type TaxRecordDetails2 struct {
	Prd *TaxPeriod2                        `xml:"Prd"`
	Amt *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
}

// TaxRecordPeriod1Code ...
type TaxRecordPeriod1Code string

// TechnicalInputChannel1Choice ...
type TechnicalInputChannel1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// TotalTransactions6 ...
type TotalTransactions6 struct {
	TtlNtries          *NumberAndSumOfTransactions4     `xml:"TtlNtries"`
	TtlCdtNtries       *NumberAndSumOfTransactions1     `xml:"TtlCdtNtries"`
	TtlDbtNtries       *NumberAndSumOfTransactions1     `xml:"TtlDbtNtries"`
	TtlNtriesPerBkTxCd []*TotalsPerBankTransactionCode5 `xml:"TtlNtriesPerBkTxCd"`
}

// TotalsPerBankTransactionCode5 ...
type TotalsPerBankTransactionCode5 struct {
	NbOfNtries string                         `xml:"NbOfNtries"`
	Sum        float64                        `xml:"Sum"`
	TtlNetNtry *AmountAndDirection35          `xml:"TtlNetNtry"`
	CdtNtries  *NumberAndSumOfTransactions1   `xml:"CdtNtries"`
	DbtNtries  *NumberAndSumOfTransactions1   `xml:"DbtNtries"`
	FcstInd    bool                           `xml:"FcstInd"`
	BkTxCd     *BankTransactionCodeStructure4 `xml:"BkTxCd"`
	Avlbty     []*CashAvailability1           `xml:"Avlbty"`
	Dt         *DateAndDateTime2Choice        `xml:"Dt"`
}

// TrackData1 ...
type TrackData1 struct {
	TrckNb  string `xml:"TrckNb"`
	TrckVal string `xml:"TrckVal"`
}

// TransactionAgents4 ...
type TransactionAgents4 struct {
	InstgAgt   *BranchAndFinancialInstitutionIdentification5 `xml:"InstgAgt"`
	InstdAgt   *BranchAndFinancialInstitutionIdentification5 `xml:"InstdAgt"`
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

// TransactionDates3 ...
type TransactionDates3 struct {
	AccptncDtTm             string              `xml:"AccptncDtTm"`
	TradActvtyCtrctlSttlmDt string              `xml:"TradActvtyCtrctlSttlmDt"`
	TradDt                  string              `xml:"TradDt"`
	IntrBkSttlmDt           string              `xml:"IntrBkSttlmDt"`
	StartDt                 string              `xml:"StartDt"`
	EndDt                   string              `xml:"EndDt"`
	TxDtTm                  string              `xml:"TxDtTm"`
	Prtry                   []*ProprietaryDate3 `xml:"Prtry"`
}

// TransactionEnvironment1Code ...
type TransactionEnvironment1Code string

// TransactionIdentifier1 ...
type TransactionIdentifier1 struct {
	TxDtTm string `xml:"TxDtTm"`
	TxRef  string `xml:"TxRef"`
}

// TransactionInterest4 ...
type TransactionInterest4 struct {
	TtlIntrstAndTaxAmt *ActiveOrHistoricCurrencyAndAmount `xml:"TtlIntrstAndTaxAmt"`
	Rcrd               []*InterestRecord2                 `xml:"Rcrd"`
}

// TransactionParties4 ...
type TransactionParties4 struct {
	InitgPty  *Party35Choice       `xml:"InitgPty"`
	Dbtr      *Party35Choice       `xml:"Dbtr"`
	DbtrAcct  *CashAccount24       `xml:"DbtrAcct"`
	UltmtDbtr *Party35Choice       `xml:"UltmtDbtr"`
	Cdtr      *Party35Choice       `xml:"Cdtr"`
	CdtrAcct  *CashAccount24       `xml:"CdtrAcct"`
	UltmtCdtr *Party35Choice       `xml:"UltmtCdtr"`
	TradgPty  *Party35Choice       `xml:"TradgPty"`
	Prtry     []*ProprietaryParty4 `xml:"Prtry"`
}

// TransactionPrice4Choice ...
type TransactionPrice4Choice struct {
	DealPric *Price7              `xml:"DealPric"`
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
