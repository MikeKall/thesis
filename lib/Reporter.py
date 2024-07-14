import openpyxl
import shutil
import openpyxl.styles
import aspose.cells as ac


class Reporter():

    def __init__(self):
        shutil.copyfile("report_template.xlsx", "report.xlsx")
        self.wb = openpyxl.load_workbook('report.xlsx')
        self.ws = self.wb.active
        self.font_family = 'Calibri'
        self.ws[f'B1'].font = openpyxl.styles.Font(name=self.font_family, sz=12, bold=True)
        self.ws[f'F1'].font = openpyxl.styles.Font(name=self.font_family, sz=12, bold=True)
        self.ws[f'K1'].font = openpyxl.styles.Font(name=self.font_family, sz=12, bold=True)
        
        
    def create_services_report(self, active_service_vulnerabilities, possible_service_vulnerabilities):
        
        offset = 8
        NameLabel_cell = 3
        SeviceName_cell = 3
        VulnLabel_cell = 4
        CVE_cell = 5
        Exploitability_cell = 6
        Impact_cell = 7
        Version_cell = 8
        Severity_cell = 9

        for service_name in active_service_vulnerabilities:
            self.ws[f'B{SeviceName_cell}'].value = service_name
            self.ws[f'B{CVE_cell}'] = active_service_vulnerabilities[service_name]["CVE"]
            self.ws[f'B{Exploitability_cell}'] = active_service_vulnerabilities[service_name]["Exploitability Score"]
            self.ws[f'B{Impact_cell}'] = active_service_vulnerabilities[service_name]["Impact Score"]
            self.ws[f'B{Version_cell}'] = active_service_vulnerabilities[service_name]["Service Version"]
            self.ws[f'B{Severity_cell}'] = active_service_vulnerabilities[service_name]["Severity"]

            if active_service_vulnerabilities[service_name]["Severity"] == "HIGH":
                self.ws[f'B{Severity_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="d11818")
            elif active_service_vulnerabilities[service_name]["Severity"] == "MEDIUM":
                self.ws[f'B{Severity_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="FFC300")
            elif active_service_vulnerabilities[service_name]["Severity"] == "LOW":
                self.ws[f'B{Severity_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="ecec0a")

            NameLabel_cell += offset
            VulnLabel_cell += offset
            SeviceName_cell += offset
            CVE_cell += offset
            Exploitability_cell += offset
            Impact_cell += offset
            Version_cell += offset
            Severity_cell += offset
        
        for service_name in possible_service_vulnerabilities:
            self.ws.merge_cells(f"B{NameLabel_cell}:C{NameLabel_cell}")

            self.ws[f'B{SeviceName_cell}'].value = service_name
            self.ws[f'C{CVE_cell}'] = possible_service_vulnerabilities[service_name]["CVE"]
            self.ws[f'C{Exploitability_cell}'] = possible_service_vulnerabilities[service_name]["Exploitability Score"]
            self.ws[f'C{Impact_cell}'] = possible_service_vulnerabilities[service_name]["Impact Score"]
            self.ws[f'C{Version_cell}'] = possible_service_vulnerabilities[service_name]["Service Version"]
            self.ws[f'C{Severity_cell}'] = possible_service_vulnerabilities[service_name]["Severity"]       

            if possible_service_vulnerabilities[service_name]["Severity"] == "HIGH":
                self.ws[f'C{Severity_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="d11818")
            elif possible_service_vulnerabilities[service_name]["Severity"] == "MEDIUM":
                self.ws[f'C{Severity_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="FFC300")
            elif possible_service_vulnerabilities[service_name]["Severity"] == "LOW":
                self.ws[f'C{Severity_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="ecec0a")
            
            NameLabel_cell += offset
            VulnLabel_cell += offset
            SeviceName_cell += offset
            CVE_cell += offset
            Exploitability_cell += offset
            Impact_cell += offset
            Version_cell += offset
            Severity_cell += offset

            
        limit = len(possible_service_vulnerabilities) if len(possible_service_vulnerabilities) >= len(active_service_vulnerabilities) else len(active_service_vulnerabilities)
        i = 0
        NameLabel_cell = 3
        SeviceName_cell = 3
        VulnLabel_cell = 4
        CVE_cell = 5
        Exploitability_cell = 6
        Impact_cell = 7
        Version_cell = 8
        Severity_cell = 9
        while i < limit:
            self.ws.merge_cells(f"B{NameLabel_cell}:C{NameLabel_cell}")

            self.ws[f'A{NameLabel_cell}'] = 'Service Name'
            self.ws[f'B{VulnLabel_cell}'] = 'Active Vulnerabilities'
            self.ws[f'C{VulnLabel_cell}'] = 'Possible Vulnerabilities'
            self.ws[f'A{CVE_cell}'] = "CVE"
            self.ws[f'A{Exploitability_cell}'] = "Exploitability Score"
            self.ws[f'A{Impact_cell}'] = "Impact Score"
            self.ws[f'A{Version_cell}'] = "Service Version"
            self.ws[f'A{Severity_cell}'] = "Severity"

            # Set style
            self.ws[f'A{SeviceName_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
            self.ws[f'A{CVE_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
            self.ws[f'A{Exploitability_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
            self.ws[f'A{Impact_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
            self.ws[f'A{Version_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
            self.ws[f'A{Severity_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)

            self.ws[f'B{SeviceName_cell}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
            self.ws[f'B{VulnLabel_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'B{CVE_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'B{Exploitability_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'B{Impact_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'B{Version_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'B{Severity_cell}'].font = openpyxl.styles.Font(name=self.font_family)

            self.ws[f'C{VulnLabel_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'C{CVE_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'C{Exploitability_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'C{Impact_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'C{Version_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'C{Severity_cell}'].font = openpyxl.styles.Font(name=self.font_family)

            # Allign cells
            self.ws[f'B{SeviceName_cell}'].alignment = openpyxl.styles.Alignment(horizontal='center')
            self.ws[f'A{NameLabel_cell}'].alignment = openpyxl.styles.Alignment(horizontal='center')
            self.ws[f'B{VulnLabel_cell}'].alignment = openpyxl.styles.Alignment(horizontal='center')
            self.ws[f'C{VulnLabel_cell}'].alignment = openpyxl.styles.Alignment(horizontal='center')

            self.ws[f'A{SeviceName_cell}'].alignment = openpyxl.styles.Alignment(horizontal='right')
            self.ws[f'A{CVE_cell}'].alignment = openpyxl.styles.Alignment(horizontal='right')
            self.ws[f'A{Exploitability_cell}'].alignment = openpyxl.styles.Alignment(horizontal='right')
            self.ws[f'A{Impact_cell}'].alignment = openpyxl.styles.Alignment(horizontal='right')
            self.ws[f'A{Version_cell}'].alignment = openpyxl.styles.Alignment(horizontal='right')
            self.ws[f'A{Severity_cell}'].alignment = openpyxl.styles.Alignment(horizontal='right')

            self.ws[f'C{CVE_cell}'].alignment = openpyxl.styles.Alignment(horizontal='left')
            self.ws[f'C{Exploitability_cell}'].alignment = openpyxl.styles.Alignment(horizontal='left')
            self.ws[f'C{Impact_cell}'].alignment = openpyxl.styles.Alignment(horizontal='left')
            self.ws[f'C{Version_cell}'].alignment = openpyxl.styles.Alignment(horizontal='left')
            self.ws[f'C{Severity_cell}'].alignment = openpyxl.styles.Alignment(horizontal='left')

            NameLabel_cell += offset
            VulnLabel_cell += offset
            SeviceName_cell += offset
            CVE_cell += offset
            Exploitability_cell += offset
            Impact_cell += offset
            Version_cell += offset
            Severity_cell += offset
            i += 1

        # Save the workbook
        self.wb.save('report.xlsx')
        print("Report file saved as report.xlsx")
    
    def create_user_report(self, vulnerable_users, high_privilaged_users):
        starting_cell = 4
        self.ws[f'G{starting_cell-1}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)
        self.ws[f'F{starting_cell-1}'].font = openpyxl.styles.Font(name=self.font_family, bold=True)

        for user in high_privilaged_users:
            self.ws[f'G{starting_cell}'] = f"{user} member of {high_privilaged_users[user]}"
            self.ws[f'G{starting_cell}'].font = openpyxl.styles.Font(name=self.font_family)
            self.ws[f'G{starting_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="d11818")
            starting_cell += 1
        
        starting_cell = 4
        for user in vulnerable_users:
            if not user in high_privilaged_users:
                self.ws[f'F{starting_cell}'] = user
                self.ws[f'F{starting_cell}'].font = openpyxl.styles.Font(name=self.font_family)
                self.ws[f'F{starting_cell}'].fill = openpyxl.styles.PatternFill("solid", fgColor="ecec0a")
                starting_cell += 1
        
        self.wb.save('report.xlsx')


    def xlsx_to_pdf(self, xlsx_file, pdf_file):
        workbook = ac.Workbook(xlsx_file)
        workbook.save(pdf_file)