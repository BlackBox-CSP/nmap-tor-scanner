
def Excel2CSV(ExcelFile, SheetName, CSVFile):
    workbook = xlrd.open_workbook(ExcelFile)
    try:
        worksheet = workbook.sheet_by_name(SheetName)
    except xlrd.biffh.XLRDError:
        print "Missing portmap for switch " + str(SheetName)
        print "Exiting program.  Check spelling of Sheet name"
        quit()

    csvfile = open(CSVFile, 'wb')
    wr = csv.writer(csvfile, quotechar="'", quoting=csv.QUOTE_ALL)

    for rownum in xrange(worksheet.nrows):
        wr.writerow(
            list(x.encode('utf-8') if type(x) == type(u'') else x
                 for x in worksheet.row_values(rownum)))
    csvfile.close()