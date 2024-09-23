import re

def check_sync_standby_str(dnlist, output):
    if output.strip() == '' or output.strip() == '*':
        return output.strip()
    
    if '(' in output:
        # output: 'ANY 1 (dn_6002, dn_6004), ANY 3 (dn_6003, dn_6005, dn_6006)'
        output_dn_list = re.findall(r'(?:\w+\s+)?\d+\s+\(.*?\)', output)
        # output_dn_list: ['ANY 1 (dn_6002, dn_6004)', 'ANY 3 (dn_6003, dn_6005, dn_6006)']
        output_dn_list = delete_sync_node_para(dnlist, output_dn_list)
        output_dn_str = ",".join(output_dn_list)
    else:
        output_dn_list = [item.strip() for item in output.strip().split(',')]
        output_dn_str = delete_sync_node_para_no_bracket(dnlist, output_dn_list)
    
    return output_dn_str

def delete_sync_node_para_no_bracket(dnlist, origin_list):
    res_str = ""
    for dninst in dnlist:
        if dninst in origin_list:
            origin_list.remove(dninst)
            res_str = ','.join(origin_list)
    return res_str

def delete_sync_node_para(dnlist, origin_list):
    res_list = []
    for origin in origin_list:
        res_str = ""
        output_no = '0'
        count_dn = 0
        output_dn_pre = re.findall(r'([^\(]+?)\s*\([^)]*\)', origin)[0]
        # get the value inside bracket
        output_dn = re.findall(r'\((.*)\)', origin)[0]
        # remove spaces
        output_dn_nospace = re.sub(' *', '', output_dn)
        init_no = len(output_dn_nospace.split(","))
        output_no = re.findall(r'\d+', output_dn_pre)[0]
        for dninst in dnlist:
            if dninst in output_dn:
                output_list = output_dn_nospace.split(",")
                output_list.remove(dninst)
                output_dn_nospace = ','.join(output_list)
                init_no -= 1
                count_dn += 1

            if output_dn_nospace == "":
                continue
            output_dn_nospace = "(" + output_dn_nospace + ")"
            res_str += output_dn_pre + output_dn_nospace
            res_str = delete_sync_node_no(output_no, init_no, count_dn, res_str)
            res_list.append(res_str)
    return res_list

def delete_sync_node_no(output_no, init_no, count_dn, output_result):
    output_new_no = '1'
    quorum_no = int(init_no / 2) + 1
    half_no = quorum_no - 1
    
    if count_dn == 0 or output_no == '0':
        return output_result
    if int(output_no) == quorum_no:
        output_new_no = str(int(init_no / 2) + 1)
        output_result = output_result.replace(output_no, output_new_no, 1)
        return output_result
    elif int(output_no) > half_no and (int(output_no) - count_dn) > 0:
        output_new_no = str(int(output_no) - count_dn)
    elif int(output_no) > half_no and (int(output_no) - count_dn) <= 0:
        output_new_no = '1'
    elif int(output_no) < half_no and int(output_no) <= init_no:
        output_new_no = output_no
    elif half_no > int(output_no) > init_no:
        output_new_no = str(init_no)
    output_result = output_result.replace(output_no, output_new_no, 1)
    return output_result
    
def test_sync_standby_name():
    dnlist = ["dn_6003"]
    output = ""
    expect_output = ""
    assert expect_output == check_sync_standby_str(dnlist, output)

    output = "*"
    expect_output = "*"
    assert expect_output == check_sync_standby_str(dnlist, output)
    
    # ANY grouping
    output = "ANY 1 (dn_6002), ANY 1 (dn_6003)"
    expect_output = "ANY 1 (dn_6002)"
    assert expect_output.replace(" ", "") == check_sync_standby_str(dnlist, output).replace(" ", "")

    output = "ANY 1 (dn_6002, dn_6003)"
    expect_output = "ANY 1 (dn_6002)"
    assert expect_output.replace(" ", "") == check_sync_standby_str(dnlist, output).replace(" ", "")

    output = "ANY 1 (dn_6002, dn_6004), ANY 1 (dn_6003, dn_6005)"
    expect_output = "ANY 1 (dn_6002, dn_6004), ANY 1 (dn_6005)"
    assert expect_output.replace(" ", "") == check_sync_standby_str(dnlist, output).replace(" ", "")

    output = "ANY 1 (dn_6002, dn_6004), ANY 1 (dn_6003)"
    expect_output = "ANY 1 (dn_6002, dn_6004)"
    assert expect_output.replace(" ", "") == check_sync_standby_str(dnlist, output).replace(" ", "")

    output = "ANY 1 (dn_6002, dn_6004), ANY 1 (dn_6005)"
    expect_output = "ANY 1 (dn_6002, dn_6004), ANY 1 (dn_6005)"
    assert expect_output.replace(" ", "") == check_sync_standby_str(dnlist, output).replace(" ", "")

    output = "ANY 1 (dn_6002, dn_6004), ANY 3 (dn_6003, dn_6005, dn_6006)"
    expect_output = "ANY 1 (dn_6002, dn_6004), ANY 2 (dn_6005, dn_6006)"
    assert expect_output.replace(" ", "") == check_sync_standby_str(dnlist, output).replace(" ", "")

    # FIRST grouping
    output = "FIRST 2 (dn_6002, dn_6003)"
    expect_output = "FIRST 1 (dn_6002)"
    assert expect_output.replace(" ", "") == check_sync_standby_str(dnlist, output).replace(" ", "")


    output = "FIRST 1 (dn_6002, dn_6003), FIRST 1 (dn_6004, dn_6005) "
    expect_output = "FIRST 1 (dn_6002), FIRST 1 (dn_6004, dn_6005) "
    assert expect_output.replace(" ", "") == check_sync_standby_str(dnlist, output).replace(" ", "")

    # no grouping
    output = "2 (dn_6002, dn_6003)"
    expect_output = "1 (dn_6002)"
    assert expect_output.replace(" ", "") == check_sync_standby_str(dnlist, output).replace(" ", "")

    output = "1 (dn_6003)"
    expect_output = ""
    assert expect_output.replace(" ", "") == check_sync_standby_str(dnlist, output).replace(" ", "")

    # no backet
    output = "dn_6002, dn_6003"
    expect_output = "dn_6002"
    assert expect_output.replace(" ", "") == check_sync_standby_str(dnlist, output).replace(" ", "")

if __name__ == '__main__':
    test_sync_standby_name()