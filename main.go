package main

import (
	"fmt"
	"xml-sig4/xmldsig"
)

func main() {
	// Generate a key and self-signed certificate for signing
	toBeSigned:= `<?xml version="1.0" encoding="UTF-8"?>
			<Message xmlns="urn:worldwire">
				<AppHdr>
					<Fr xmlns="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">
						<FIId>
							<FinInstnId>
								<BICFI>SGPTTEST003</BICFI>
								<Othr>
									<Id>testparticipant3dev</Id>
								</Othr>
							</FinInstnId>
						</FIId>
					</Fr>
					<To xmlns="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">
						<FIId>
							<FinInstnId>
								<BICFI>WORLDWIRE00</BICFI>
								<Othr>
									<Id>WW</Id>
								</Othr>
							</FinInstnId>
						</FIId>
					</To>
					<BizMsgIdr xmlns="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">B20190819SGPTTEST003BAA4710449</BizMsgIdr>
					<MsgDefIdr xmlns="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">pacs.009.001.08</MsgDefIdr>
					<CreDt xmlns="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">2019-08-19T13:12:18Z</CreDt>
				</AppHdr>
				<FICdtTrf>
					<GrpHdr xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.009.001.08">
						<MsgId>SGDDO19082019SGPTTEST00377793380333</MsgId>
						<CreDtTm>2019-08-19T13:12:18</CreDtTm>
						<NbOfTxs>1</NbOfTxs>
						<SttlmInf>
							<SttlmMtd>WWDA</SttlmMtd>
							<SttlmAcct>
								<Id>
									<Othr>
										<Id>testparticipant3dev</Id>
									</Othr>
								</Id>
								<Nm>issuing</Nm>
							</SttlmAcct>
						</SttlmInf>
						<PmtTpInf>
							<SvcLvl>
								<Prtry>testparticipant3dev</Prtry>
							</SvcLvl>
						</PmtTpInf>
						<InstgAgt>
							<FinInstnId>
								<BICFI>SGPTTEST003</BICFI>
								<Othr>
									<Id>testparticipant3dev</Id>
								</Othr>
							</FinInstnId>
						</InstgAgt>
						<InstdAgt>
							<FinInstnId>
								<BICFI>SGPTTEST004</BICFI>
								<Othr>
									<Id>testparticipant4dev</Id>
								</Othr>
							</FinInstnId>
						</InstdAgt>
					</GrpHdr>
					<CdtTrfTxInf xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.009.001.08">
						<PmtId>
							<InstrId>SGDDO20190819SGPTTEST003B3889747663</InstrId>
							<EndToEndId>SGDDO19082019SGPTTEST00377793380333</EndToEndId>
							<TxId>SGDDO19082019SGPTTEST00377793380333</TxId>
						</PmtId>
						<IntrBkSttlmAmt Ccy="USD">0.02</IntrBkSttlmAmt>
						<IntrBkSttlmDt>2019-08-19</IntrBkSttlmDt>
						<Dbtr>
							<FinInstnId>
								<Nm>testparticipant3dev</Nm>
								<PstlAdr>
									<StrtNm>Times Square</StrtNm>
									<BldgNb>7</BldgNb>
									<PstCd>NY 10036</PstCd>
									<TwnNm>New York</TwnNm>
									<Ctry>US</Ctry>
								</PstlAdr>
							</FinInstnId>
						</Dbtr>
						<DbtrAgt>
							<FinInstnId>
								<BICFI>SGPTTEST003</BICFI>
								<Othr>
									<Id>testparticipant3dev</Id>
								</Othr>
							</FinInstnId>
						</DbtrAgt>
						<CdtrAgt>
							<FinInstnId>
								<BICFI>SGPTTEST004</BICFI>
								<Othr>
									<Id>testparticipant4dev</Id>
								</Othr>
							</FinInstnId>
						</CdtrAgt>
						<Cdtr>
							<FinInstnId>
								<Nm>testparticipant4dev</Nm>
								<PstlAdr>
									<StrtNm>Mark Lane</StrtNm>
									<BldgNb>55</BldgNb>
									<PstCd>EC3R7NE</PstCd>
									<TwnNm>London</TwnNm>
									<Ctry>GB</Ctry>
									<AdrLine>Corn Exchange 5th Floor</AdrLine>
								</PstlAdr>
							</FinInstnId>
						</Cdtr>
						<SplmtryData>
							<PlcAndNm>payout</PlcAndNm>
							<Envlp>
								<Id>5cca8fe18fc867ceda461079</Id>
							</Envlp>
						</SplmtryData>
						<SplmtryData>
							<PlcAndNm>fee</PlcAndNm>
							<Envlp>
								<Id>b63hxba8h7331</Id>
							</Envlp>
						</SplmtryData>
					</CdtTrfTxInf>
				</FICdtTrf>
			</Message>`

	for i := 1; i <= 100; i++ {
		signedXML, err := xmldsig.SignXML(toBeSigned, "Public key")
		if(err != nil){
			fmt.Println(err)
		}
		xmldsig.VerifySignature(signedXML)
	}
}
