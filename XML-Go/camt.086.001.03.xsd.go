package schema

// Document ...
type Document *Document

// AccountIdentification4Choice ...
type AccountIdentification4Choice struct {
	IBAN string                         `xml:"IBAN"`
	Othr *GenericAccountIdentification1 `xml:"Othr"`
}

// AccountLevel1Code ...
type AccountLevel1Code string

// AccountLevel2Code ...
type AccountLevel2Code string

// AccountSchemeName1Choice ...
type AccountSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// AccountTax1 ...
type AccountTax1 struct {
	ClctnMtd   string                    `xml:"ClctnMtd"`
	Rgn        string                    `xml:"Rgn"`
	NonResCtry *ResidenceLocation1Choice `xml:"NonResCtry"`
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

// AddressType3Choice ...
type AddressType3Choice struct {
	Cd    string                   `xml:"Cd"`
	Prtry *GenericIdentification30 `xml:"Prtry"`
}

// AmountAndDirection34 ...
type AmountAndDirection34 struct {
	Amt *ActiveOrHistoricCurrencyAndAmount `xml:"Amt"`
	Sgn bool                               `xml:"Sgn"`
}

// AnyBICDec2014Identifier ...
type AnyBICDec2014Identifier string

// BICFIDec2014Identifier ...
type BICFIDec2014Identifier string

// BalanceAdjustment1 ...
type BalanceAdjustment1 struct {
	Tp                string                `xml:"Tp"`
	Desc              string                `xml:"Desc"`
	BalAmt            *AmountAndDirection34 `xml:"BalAmt"`
	AvrgAmt           *AmountAndDirection34 `xml:"AvrgAmt"`
	ErrDt             string                `xml:"ErrDt"`
	PstngDt           string                `xml:"PstngDt"`
	Days              float64               `xml:"Days"`
	EarngsAdjstmntAmt *AmountAndDirection34 `xml:"EarngsAdjstmntAmt"`
}

// BalanceAdjustmentType1Code ...
type BalanceAdjustmentType1Code string

// BankServicesBillingStatementV03 ...
type BankServicesBillingStatementV03 struct {
	RptHdr      *ReportHeader6     `xml:"RptHdr"`
	BllgStmtGrp []*StatementGroup3 `xml:"BllgStmtGrp"`
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

// BillingBalance1 ...
type BillingBalance1 struct {
	Tp    *BillingBalanceType1Choice `xml:"Tp"`
	Val   *AmountAndDirection34      `xml:"Val"`
	CcyTp string                     `xml:"CcyTp"`
}

// BillingBalanceType1Choice ...
type BillingBalanceType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// BillingChargeMethod1Code ...
type BillingChargeMethod1Code string

// BillingCompensation1 ...
type BillingCompensation1 struct {
	Tp    *BillingCompensationType1Choice `xml:"Tp"`
	Val   *AmountAndDirection34           `xml:"Val"`
	CcyTp string                          `xml:"CcyTp"`
}

// BillingCompensationType1Choice ...
type BillingCompensationType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// BillingCurrencyType1Code ...
type BillingCurrencyType1Code string

// BillingCurrencyType2Code ...
type BillingCurrencyType2Code string

// BillingMethod1 ...
type BillingMethod1 struct {
	SvcChrgHstAmt *AmountAndDirection34   `xml:"SvcChrgHstAmt"`
	SvcTax        *BillingServicesAmount1 `xml:"SvcTax"`
	TtlChrg       *BillingServicesAmount2 `xml:"TtlChrg"`
	TaxId         []*BillingServicesTax1  `xml:"TaxId"`
}

// BillingMethod1Choice ...
type BillingMethod1Choice struct {
	MtdA *BillingMethod1 `xml:"MtdA"`
	MtdB *BillingMethod2 `xml:"MtdB"`
	MtdD *BillingMethod3 `xml:"MtdD"`
}

// BillingMethod2 ...
type BillingMethod2 struct {
	SvcChrgHstAmt *AmountAndDirection34   `xml:"SvcChrgHstAmt"`
	SvcTax        *BillingServicesAmount1 `xml:"SvcTax"`
	TaxId         []*BillingServicesTax1  `xml:"TaxId"`
}

// BillingMethod3 ...
type BillingMethod3 struct {
	SvcTaxPricAmt *AmountAndDirection34  `xml:"SvcTaxPricAmt"`
	TaxId         []*BillingServicesTax2 `xml:"TaxId"`
}

// BillingMethod4 ...
type BillingMethod4 struct {
	SvcDtl   []*BillingServiceParameters2 `xml:"SvcDtl"`
	TaxClctn *TaxCalculation1             `xml:"TaxClctn"`
}

// BillingPrice1 ...
type BillingPrice1 struct {
	Ccy      string                `xml:"Ccy"`
	UnitPric *AmountAndDirection34 `xml:"UnitPric"`
	Mtd      string                `xml:"Mtd"`
	Rule     string                `xml:"Rule"`
}

// BillingRate1 ...
type BillingRate1 struct {
	Id        *BillingRateIdentification1Choice `xml:"Id"`
	Val       float64                           `xml:"Val"`
	DaysInPrd float64                           `xml:"DaysInPrd"`
	DaysInYr  float64                           `xml:"DaysInYr"`
}

// BillingRateIdentification1Choice ...
type BillingRateIdentification1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// BillingService2 ...
type BillingService2 struct {
	SvcDtl            *BillingServiceParameters3 `xml:"SvcDtl"`
	Pric              *BillingPrice1             `xml:"Pric"`
	PmtMtd            string                     `xml:"PmtMtd"`
	OrgnlChrgPric     *AmountAndDirection34      `xml:"OrgnlChrgPric"`
	OrgnlChrgSttlmAmt *AmountAndDirection34      `xml:"OrgnlChrgSttlmAmt"`
	BalReqrdAcctAmt   *AmountAndDirection34      `xml:"BalReqrdAcctAmt"`
	TaxDsgnt          *ServiceTaxDesignation1    `xml:"TaxDsgnt"`
	TaxClctn          *BillingMethod1Choice      `xml:"TaxClctn"`
}

// BillingServiceAdjustment1 ...
type BillingServiceAdjustment1 struct {
	Tp           string                            `xml:"Tp"`
	Desc         string                            `xml:"Desc"`
	Amt          *AmountAndDirection34             `xml:"Amt"`
	BalReqrdAmt  *AmountAndDirection34             `xml:"BalReqrdAmt"`
	ErrDt        string                            `xml:"ErrDt"`
	AdjstmntId   string                            `xml:"AdjstmntId"`
	SubSvc       *BillingSubServiceIdentification1 `xml:"SubSvc"`
	PricChng     *AmountAndDirection34             `xml:"PricChng"`
	OrgnlPric    *AmountAndDirection34             `xml:"OrgnlPric"`
	NewPric      *AmountAndDirection34             `xml:"NewPric"`
	VolChng      float64                           `xml:"VolChng"`
	OrgnlVol     float64                           `xml:"OrgnlVol"`
	NewVol       float64                           `xml:"NewVol"`
	OrgnlChrgAmt *AmountAndDirection34             `xml:"OrgnlChrgAmt"`
	NewChrgAmt   *AmountAndDirection34             `xml:"NewChrgAmt"`
}

// BillingServiceCommonIdentification1 ...
type BillingServiceCommonIdentification1 struct {
	Issr string `xml:"Issr"`
	Id   string `xml:"Id"`
}

// BillingServiceIdentification2 ...
type BillingServiceIdentification2 struct {
	Id     string                            `xml:"Id"`
	SubSvc *BillingSubServiceIdentification1 `xml:"SubSvc"`
	Desc   string                            `xml:"Desc"`
}

// BillingServiceIdentification3 ...
type BillingServiceIdentification3 struct {
	Id     string                               `xml:"Id"`
	SubSvc *BillingSubServiceIdentification1    `xml:"SubSvc"`
	Desc   string                               `xml:"Desc"`
	CmonCd *BillingServiceCommonIdentification1 `xml:"CmonCd"`
	BkTxCd *BankTransactionCodeStructure4       `xml:"BkTxCd"`
	SvcTp  string                               `xml:"SvcTp"`
}

// BillingServiceParameters2 ...
type BillingServiceParameters2 struct {
	BkSvc      *BillingServiceIdentification2 `xml:"BkSvc"`
	Vol        float64                        `xml:"Vol"`
	UnitPric   *AmountAndDirection34          `xml:"UnitPric"`
	SvcChrgAmt *AmountAndDirection34          `xml:"SvcChrgAmt"`
}

// BillingServiceParameters3 ...
type BillingServiceParameters3 struct {
	BkSvc *BillingServiceIdentification3 `xml:"BkSvc"`
	Vol   float64                        `xml:"Vol"`
}

// BillingServicesAmount1 ...
type BillingServicesAmount1 struct {
	HstAmt   *AmountAndDirection34 `xml:"HstAmt"`
	PricgAmt *AmountAndDirection34 `xml:"PricgAmt"`
}

// BillingServicesAmount2 ...
type BillingServicesAmount2 struct {
	HstAmt   *AmountAndDirection34 `xml:"HstAmt"`
	SttlmAmt *AmountAndDirection34 `xml:"SttlmAmt"`
	PricgAmt *AmountAndDirection34 `xml:"PricgAmt"`
}

// BillingServicesAmount3 ...
type BillingServicesAmount3 struct {
	SrcAmt *AmountAndDirection34 `xml:"SrcAmt"`
	HstAmt *AmountAndDirection34 `xml:"HstAmt"`
}

// BillingServicesTax1 ...
type BillingServicesTax1 struct {
	Nb       string                `xml:"Nb"`
	Desc     string                `xml:"Desc"`
	Rate     float64               `xml:"Rate"`
	HstAmt   *AmountAndDirection34 `xml:"HstAmt"`
	PricgAmt *AmountAndDirection34 `xml:"PricgAmt"`
}

// BillingServicesTax2 ...
type BillingServicesTax2 struct {
	Nb       string                `xml:"Nb"`
	Desc     string                `xml:"Desc"`
	Rate     float64               `xml:"Rate"`
	PricgAmt *AmountAndDirection34 `xml:"PricgAmt"`
}

// BillingServicesTax3 ...
type BillingServicesTax3 struct {
	Nb        string                `xml:"Nb"`
	Desc      string                `xml:"Desc"`
	Rate      float64               `xml:"Rate"`
	TtlTaxAmt *AmountAndDirection34 `xml:"TtlTaxAmt"`
}

// BillingStatement3 ...
type BillingStatement3 struct {
	StmtId      string                       `xml:"StmtId"`
	FrToDt      *DatePeriod1                 `xml:"FrToDt"`
	CreDtTm     string                       `xml:"CreDtTm"`
	Sts         string                       `xml:"Sts"`
	AcctChrtcs  *CashAccountCharacteristics3 `xml:"AcctChrtcs"`
	RateData    []*BillingRate1              `xml:"RateData"`
	CcyXchg     []*CurrencyExchange6         `xml:"CcyXchg"`
	Bal         []*BillingBalance1           `xml:"Bal"`
	Compstn     []*BillingCompensation1      `xml:"Compstn"`
	Svc         []*BillingService2           `xml:"Svc"`
	TaxRgn      []*BillingTaxRegion2         `xml:"TaxRgn"`
	BalAdjstmnt []*BalanceAdjustment1        `xml:"BalAdjstmnt"`
	SvcAdjstmnt []*BillingServiceAdjustment1 `xml:"SvcAdjstmnt"`
}

// BillingStatementStatus1Code ...
type BillingStatementStatus1Code string

// BillingSubServiceIdentification1 ...
type BillingSubServiceIdentification1 struct {
	Issr *BillingSubServiceQualifier1Choice `xml:"Issr"`
	Id   string                             `xml:"Id"`
}

// BillingSubServiceQualifier1Choice ...
type BillingSubServiceQualifier1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// BillingSubServiceQualifier1Code ...
type BillingSubServiceQualifier1Code string

// BillingTaxCalculationMethod1Code ...
type BillingTaxCalculationMethod1Code string

// BillingTaxIdentification2 ...
type BillingTaxIdentification2 struct {
	VATRegnNb string    `xml:"VATRegnNb"`
	TaxRegnNb string    `xml:"TaxRegnNb"`
	TaxCtct   *Contact4 `xml:"TaxCtct"`
}

// BillingTaxRegion2 ...
type BillingTaxRegion2 struct {
	RgnNb       string                     `xml:"RgnNb"`
	RgnNm       string                     `xml:"RgnNm"`
	CstmrTaxId  string                     `xml:"CstmrTaxId"`
	PtDt        string                     `xml:"PtDt"`
	SndgFI      *BillingTaxIdentification2 `xml:"SndgFI"`
	InvcNb      string                     `xml:"InvcNb"`
	MtdC        *BillingMethod4            `xml:"MtdC"`
	SttlmAmt    *AmountAndDirection34      `xml:"SttlmAmt"`
	TaxDueToRgn *AmountAndDirection34      `xml:"TaxDueToRgn"`
}

// BranchAndFinancialInstitutionIdentification6 ...
type BranchAndFinancialInstitutionIdentification6 struct {
	FinInstnId *FinancialInstitutionIdentification18 `xml:"FinInstnId"`
	BrnchId    *BranchData3                          `xml:"BrnchId"`
}

// BranchData3 ...
type BranchData3 struct {
	Id      string           `xml:"Id"`
	LEI     string           `xml:"LEI"`
	Nm      string           `xml:"Nm"`
	PstlAdr *PostalAddress24 `xml:"PstlAdr"`
}

// CashAccount38 ...
type CashAccount38 struct {
	Id   *AccountIdentification4Choice `xml:"Id"`
	Tp   *CashAccountType2Choice       `xml:"Tp"`
	Ccy  string                        `xml:"Ccy"`
	Nm   string                        `xml:"Nm"`
	Prxy *ProxyAccountIdentification1  `xml:"Prxy"`
}

// CashAccountCharacteristics3 ...
type CashAccountCharacteristics3 struct {
	AcctLvl      string                                        `xml:"AcctLvl"`
	CshAcct      *CashAccount38                                `xml:"CshAcct"`
	AcctSvcr     *BranchAndFinancialInstitutionIdentification6 `xml:"AcctSvcr"`
	PrntAcct     *ParentCashAccount3                           `xml:"PrntAcct"`
	CompstnMtd   string                                        `xml:"CompstnMtd"`
	DbtAcct      *AccountIdentification4Choice                 `xml:"DbtAcct"`
	DelydDbtDt   string                                        `xml:"DelydDbtDt"`
	SttlmAdvc    string                                        `xml:"SttlmAdvc"`
	AcctBalCcyCd string                                        `xml:"AcctBalCcyCd"`
	SttlmCcyCd   string                                        `xml:"SttlmCcyCd"`
	HstCcyCd     string                                        `xml:"HstCcyCd"`
	Tax          *AccountTax1                                  `xml:"Tax"`
	AcctSvcrCtct *Contact4                                     `xml:"AcctSvcrCtct"`
}

// CashAccountType2Choice ...
type CashAccountType2Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
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

// CompensationMethod1Code ...
type CompensationMethod1Code string

// Contact4 ...
type Contact4 struct {
	NmPrfx    string           `xml:"NmPrfx"`
	Nm        string           `xml:"Nm"`
	PhneNb    string           `xml:"PhneNb"`
	MobNb     string           `xml:"MobNb"`
	FaxNb     string           `xml:"FaxNb"`
	EmailAdr  string           `xml:"EmailAdr"`
	EmailPurp string           `xml:"EmailPurp"`
	JobTitl   string           `xml:"JobTitl"`
	Rspnsblty string           `xml:"Rspnsblty"`
	Dept      string           `xml:"Dept"`
	Othr      []*OtherContact1 `xml:"Othr"`
	PrefrdMtd string           `xml:"PrefrdMtd"`
}

// CountryCode ...
type CountryCode string

// CurrencyExchange6 ...
type CurrencyExchange6 struct {
	SrcCcy   string  `xml:"SrcCcy"`
	TrgtCcy  string  `xml:"TrgtCcy"`
	XchgRate float64 `xml:"XchgRate"`
	Desc     string  `xml:"Desc"`
	UnitCcy  string  `xml:"UnitCcy"`
	Cmnts    string  `xml:"Cmnts"`
	QtnDt    string  `xml:"QtnDt"`
}

// DatePeriod1 ...
type DatePeriod1 struct {
	FrDt string `xml:"FrDt"`
	ToDt string `xml:"ToDt"`
}

// DecimalNumber ...
type DecimalNumber float64

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

// ExternalBillingBalanceType1Code ...
type ExternalBillingBalanceType1Code string

// ExternalBillingCompensationType1Code ...
type ExternalBillingCompensationType1Code string

// ExternalBillingRateIdentification1Code ...
type ExternalBillingRateIdentification1Code string

// ExternalCashAccountType1Code ...
type ExternalCashAccountType1Code string

// ExternalClearingSystemIdentification1Code ...
type ExternalClearingSystemIdentification1Code string

// ExternalFinancialInstitutionIdentification1Code ...
type ExternalFinancialInstitutionIdentification1Code string

// ExternalOrganisationIdentification1Code ...
type ExternalOrganisationIdentification1Code string

// ExternalProxyAccountType1Code ...
type ExternalProxyAccountType1Code string

// FinancialIdentificationSchemeName1Choice ...
type FinancialIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// FinancialInstitutionIdentification18 ...
type FinancialInstitutionIdentification18 struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	LEI         string                               `xml:"LEI"`
	Nm          string                               `xml:"Nm"`
	PstlAdr     *PostalAddress24                     `xml:"PstlAdr"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
}

// FinancialInstitutionIdentification19 ...
type FinancialInstitutionIdentification19 struct {
	BICFI       string                               `xml:"BICFI"`
	ClrSysMmbId *ClearingSystemMemberIdentification2 `xml:"ClrSysMmbId"`
	LEI         string                               `xml:"LEI"`
	Othr        *GenericFinancialIdentification1     `xml:"Othr"`
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

// GenericIdentification30 ...
type GenericIdentification30 struct {
	Id      string `xml:"Id"`
	Issr    string `xml:"Issr"`
	SchmeNm string `xml:"SchmeNm"`
}

// GenericOrganisationIdentification1 ...
type GenericOrganisationIdentification1 struct {
	Id      string                                       `xml:"Id"`
	SchmeNm *OrganisationIdentificationSchemeName1Choice `xml:"SchmeNm"`
	Issr    string                                       `xml:"Issr"`
}

// IBAN2007Identifier ...
type IBAN2007Identifier string

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// LEIIdentifier ...
type LEIIdentifier string

// Max105Text ...
type Max105Text string

// Max10Text ...
type Max10Text string

// Max128Text ...
type Max128Text string

// Max12Text ...
type Max12Text string

// Max140Text ...
type Max140Text string

// Max16Text ...
type Max16Text string

// Max2048Text ...
type Max2048Text string

// Max20Text ...
type Max20Text string

// Max34Text ...
type Max34Text string

// Max35Text ...
type Max35Text string

// Max40Text ...
type Max40Text string

// Max4Text ...
type Max4Text string

// Max5NumericText ...
type Max5NumericText string

// Max6Text ...
type Max6Text string

// Max70Text ...
type Max70Text string

// Max8Text ...
type Max8Text string

// NamePrefix2Code ...
type NamePrefix2Code string

// Number ...
type Number float64

// OrganisationIdentification29 ...
type OrganisationIdentification29 struct {
	AnyBIC string                                `xml:"AnyBIC"`
	LEI    string                                `xml:"LEI"`
	Othr   []*GenericOrganisationIdentification1 `xml:"Othr"`
}

// OrganisationIdentificationSchemeName1Choice ...
type OrganisationIdentificationSchemeName1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// OtherContact1 ...
type OtherContact1 struct {
	ChanlTp string `xml:"ChanlTp"`
	Id      string `xml:"Id"`
}

// Pagination1 ...
type Pagination1 struct {
	PgNb      string `xml:"PgNb"`
	LastPgInd bool   `xml:"LastPgInd"`
}

// ParentCashAccount3 ...
type ParentCashAccount3 struct {
	Lvl  string                                        `xml:"Lvl"`
	Id   *CashAccount38                                `xml:"Id"`
	Svcr *BranchAndFinancialInstitutionIdentification6 `xml:"Svcr"`
}

// Party43Choice ...
type Party43Choice struct {
	OrgId *OrganisationIdentification29         `xml:"OrgId"`
	FIId  *FinancialInstitutionIdentification19 `xml:"FIId"`
}

// PartyIdentification138 ...
type PartyIdentification138 struct {
	Nm        string           `xml:"Nm"`
	LglNm     string           `xml:"LglNm"`
	PstlAdr   *PostalAddress24 `xml:"PstlAdr"`
	Id        *Party43Choice   `xml:"Id"`
	CtryOfRes string           `xml:"CtryOfRes"`
	CtctDtls  *Contact4        `xml:"CtctDtls"`
}

// PercentageRate ...
type PercentageRate float64

// PhoneNumber ...
type PhoneNumber string

// PlusOrMinusIndicator ...
type PlusOrMinusIndicator bool

// PostalAddress24 ...
type PostalAddress24 struct {
	AdrTp       *AddressType3Choice `xml:"AdrTp"`
	Dept        string              `xml:"Dept"`
	SubDept     string              `xml:"SubDept"`
	StrtNm      string              `xml:"StrtNm"`
	BldgNb      string              `xml:"BldgNb"`
	BldgNm      string              `xml:"BldgNm"`
	Flr         string              `xml:"Flr"`
	PstBx       string              `xml:"PstBx"`
	Room        string              `xml:"Room"`
	PstCd       string              `xml:"PstCd"`
	TwnNm       string              `xml:"TwnNm"`
	TwnLctnNm   string              `xml:"TwnLctnNm"`
	DstrctNm    string              `xml:"DstrctNm"`
	CtrySubDvsn string              `xml:"CtrySubDvsn"`
	Ctry        string              `xml:"Ctry"`
	AdrLine     []string            `xml:"AdrLine"`
}

// PreferredContactMethod1Code ...
type PreferredContactMethod1Code string

// ProprietaryBankTransactionCodeStructure1 ...
type ProprietaryBankTransactionCodeStructure1 struct {
	Cd   string `xml:"Cd"`
	Issr string `xml:"Issr"`
}

// ProxyAccountIdentification1 ...
type ProxyAccountIdentification1 struct {
	Tp *ProxyAccountType1Choice `xml:"Tp"`
	Id string                   `xml:"Id"`
}

// ProxyAccountType1Choice ...
type ProxyAccountType1Choice struct {
	Cd    string `xml:"Cd"`
	Prtry string `xml:"Prtry"`
}

// ReportHeader6 ...
type ReportHeader6 struct {
	RptId    string       `xml:"RptId"`
	MsgPgntn *Pagination1 `xml:"MsgPgntn"`
}

// ResidenceLocation1Choice ...
type ResidenceLocation1Choice struct {
	Ctry string `xml:"Ctry"`
	Area string `xml:"Area"`
}

// ServiceAdjustmentType1Code ...
type ServiceAdjustmentType1Code string

// ServicePaymentMethod1Code ...
type ServicePaymentMethod1Code string

// ServiceTaxDesignation1 ...
type ServiceTaxDesignation1 struct {
	Cd     string        `xml:"Cd"`
	Rgn    string        `xml:"Rgn"`
	TaxRsn []*TaxReason1 `xml:"TaxRsn"`
}

// ServiceTaxDesignation1Code ...
type ServiceTaxDesignation1Code string

// StatementGroup3 ...
type StatementGroup3 struct {
	GrpId        string                  `xml:"GrpId"`
	Sndr         *PartyIdentification138 `xml:"Sndr"`
	SndrIndvCtct []*Contact4             `xml:"SndrIndvCtct"`
	Rcvr         *PartyIdentification138 `xml:"Rcvr"`
	RcvrIndvCtct []*Contact4             `xml:"RcvrIndvCtct"`
	BllgStmt     []*BillingStatement3    `xml:"BllgStmt"`
}

// TaxCalculation1 ...
type TaxCalculation1 struct {
	HstCcy                string                    `xml:"HstCcy"`
	TaxblSvcChrgConvs     []*BillingServicesAmount3 `xml:"TaxblSvcChrgConvs"`
	TtlTaxblSvcChrgHstAmt *AmountAndDirection34     `xml:"TtlTaxblSvcChrgHstAmt"`
	TaxId                 []*BillingServicesTax3    `xml:"TaxId"`
	TtlTax                *AmountAndDirection34     `xml:"TtlTax"`
}

// TaxReason1 ...
type TaxReason1 struct {
	Cd     string `xml:"Cd"`
	Expltn string `xml:"Expltn"`
}

// YesNoIndicator ...
type YesNoIndicator bool
