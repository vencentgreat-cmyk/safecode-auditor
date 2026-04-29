from scanner.expression_parser import BinaryOp, parse_expression


def test_parse_in_operator_member_access():
    ast = parse_expression("request.auth.uid in resource.data.members")

    assert isinstance(ast, BinaryOp)
    assert ast.operator == "in"


def test_parse_in_operator_with_and():
    ast = parse_expression("request.auth != null && request.auth.uid in resource.data.members")

    assert isinstance(ast, BinaryOp)
    assert ast.operator == "&&"


def test_parse_in_operator_with_array_literal():
    ast = parse_expression("request.auth.uid in ['a', 'b']")

    assert isinstance(ast, BinaryOp)
    assert ast.operator == "in"
