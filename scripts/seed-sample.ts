import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["CERTHR_DB_PATH"] ?? "data/certhr.db";
const force = process.argv.includes("--force");
const dir = dirname(DB_PATH);
if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
if (force && existsSync(DB_PATH)) { unlinkSync(DB_PATH); console.log("Deleted " + DB_PATH); }

const db = new Database(DB_PATH);
db.exec(SCHEMA_SQL);

const frameworks = [
  { id: "certhr-framework", name: "Nacionalni okvir kiberneticke sigurnosti", name_en: "National Cybersecurity Framework", description: "CERT.hr okvir za zastitu informacijskih sustava i kriticne infrastrukture u Hrvatskoj.", document_count: 5 },
  { id: "nis2-hr", name: "Implementacija NIS2 u Hrvatskoj", name_en: "NIS2 Directive Implementation in Croatia", description: "Zahtjevi za implementaciju Direktive NIS2 u hrvatskom zakonodavstvu.", document_count: 1 },
  { id: "isms-certhr", name: "Upravljanje informacijskom sigurnoscu (ISMS)", name_en: "Information Security Management System", description: "CERT.hr dokumenti za uspostavu ISMS-a sukladno ISO/IEC 27001.", document_count: 2 },
];

const guidance = [
  { reference: "CERTHR-SM-01/2023", title: "Smjernice za sigurnost usluga u oblaku", title_en: "Cloud Services Security Guidelines", date: "2023-05-20", type: "guideline", series: "CERT.hr", summary: "Minimalni sigurnosni zahtjevi za usluge u oblaku koje koriste tijela javne vlasti.", full_text: "CERTHR-SM-01/2023\n\nSigurnost oblaka\n1. Procjena rizika prije migracije.\n2. Ugovorna jamstva.\n3. Rezervne kopije i oporavak.\n4. Revizija pristupa.\n5. Enkripcija podataka.", topics: "oblak,sigurnost", status: "current" },
  { reference: "CERTHR-SM-02/2023", title: "Sigurnost industrijskih upravljackih sustava (ICS/SCADA)", title_en: "ICS/SCADA Security Guidelines", date: "2023-09-10", type: "standard", series: "CERT.hr", summary: "Zastita industrijskih upravljackih sustava u sektorima energetike i vodnoga gospodarstva.", full_text: "CERTHR-SM-02/2023\n\nICS/SCADA sigurnost\n1. Segmentacija mreze OT/IT.\n2. Privilegirani pristup u OT.\n3. Krpanje komponenti.\n4. Detekcija anomalija.\n5. Planovi odgovora na incidente.", topics: "ICS,SCADA,OT", status: "current" },
  { reference: "CERTHR-P-01/2024", title: "Preporuke za visefaktorsku autentifikaciju", title_en: "Multi-Factor Authentication Recommendations", date: "2024-02-15", type: "recommendation", series: "CERT.hr", summary: "Uvodenje visefaktorske autentifikacije u informacijske sustave kriticne infrastrukture.", full_text: "CERTHR-P-01/2024\n\nMFA je kljucna mjera zastite od neovlastenog pristupa.\nPreporucene metode: FIDO2, TOTP, hardverski tokeni.\nObvezna za administratore i udaljeni pristup.", topics: "MFA,autentifikacija", status: "current" },
  { reference: "CERTHR-SM-03/2024", title: "Smjernice NIS2 za operatore kljucnih usluga", title_en: "NIS2 Guidelines for Essential Service Operators", date: "2024-06-01", type: "regulation", series: "NIS2", summary: "Implementacijske smjernice za subjekte obvezane Zakonom o kibernetickoj sigurnosti (NIS2).", full_text: "CERTHR-SM-03/2024\n\nNIS2 obveze\n1. Registracija kod CERT.hr/SOA.\n2. Sustav upravljanja kibernetickom sigurnoscu.\n3. Prijava incidenata u 24/72 sata.\n4. Procjena rizika lanca opskrbe.\n5. Penetracijsko testiranje.", topics: "NIS2,registracija,incident", status: "current" },
  { reference: "CERTHR-P-02/2024", title: "Preporuke za sigurnu primjenu UI", title_en: "AI Security Application Recommendations", date: "2024-10-15", type: "recommendation", series: "CERT.hr", summary: "Sigurno uvodenje sustava UI u tijela javne vlasti i kriticnu infrastrukturu.", full_text: "CERTHR-P-02/2024\n\nUI i kiberneticka sigurnost\n1. Procjena rizika sustava UI.\n2. Zastita podataka za obuku.\n3. Nadzor izlaza.\n4. Sukladnost s AI Act.\n5. Zabrana nepouzdanih UI sustava u KII.", topics: "UI,umjetna inteligencija", status: "current" },
];

const advisories = [
  { reference: "CERTHR-ALERT-2024-001", title: "Kriticna ranjivost u Microsoft Exchange Serveru", date: "2024-02-17", severity: "critical", affected_products: "Microsoft Exchange Server 2016, 2019", summary: "Aktivno iskoristavanje CVE-2024-21410 u Microsoft Exchange Serveru.", full_text: "CERTHR-ALERT-2024-001\n\nAktivno iskoristavanje CVE-2024-21410 (NTLM Relay).\nMjere: Zakrpa KB5035106, aktivacija EPA, nadzor NTLM zapisa.", cve_references: "CVE-2024-21410" },
  { reference: "CERTHR-ALERT-2024-002", title: "Phishing kampanja na hrvatske financijske institucije", date: "2024-07-25", severity: "high", affected_products: "Internet bankarstvo, mobilne bankovne aplikacije", summary: "Sofisticirana phishing kampanja koja cilja klijente hrvatskih banaka.", full_text: "CERTHR-ALERT-2024-002\n\nOrganizirana phishing kampanja s laznim bankovnim portalima.\nTehnikekoje koriste napadaci: SMS, lazne domene, preusmjeravanje.\nIndikatori kompromitacije dostupni registriranim subjektima.", cve_references: null },
  { reference: "CERTHR-ALERT-2024-003", title: "Ransomware kampanja na kriticnu infrastrukturu", date: "2024-09-20", severity: "critical", affected_products: "Windows Server, industrijski upravljacki sustavi", summary: "Pojacani ransomware napadi na operatore kriticne infrastrukture u Hrvatskoj.", full_text: "CERTHR-ALERT-2024-003\n\nPojacani ransomware napadi na KII u Hrvatskoj.\nVektori: RDP/VPN, ciljani phishing, lanci opskrbe.\nMjere: sigurnosne kopije izvan mreze, segmentacija, EDR, prijava 24h.", cve_references: null },
];

const iF = db.prepare("INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count) VALUES (@id, @name, @name_en, @description, @document_count)");
const iG = db.prepare("INSERT OR REPLACE INTO guidance (reference, title, title_en, date, type, series, summary, full_text, topics, status) VALUES (@reference, @title, @title_en, @date, @type, @series, @summary, @full_text, @topics, @status)");
const iA = db.prepare("INSERT OR REPLACE INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references) VALUES (@reference, @title, @date, @severity, @affected_products, @summary, @full_text, @cve_references)");

for (const f of frameworks) iF.run(f);
for (const g of guidance) iG.run(g);
for (const a of advisories) iA.run(a);

console.log("Seeded " + frameworks.length + " frameworks, " + guidance.length + " guidance, " + advisories.length + " advisories into " + DB_PATH);
db.close();
