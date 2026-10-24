from elfresolver.symbols import Function, PLTEntry, String
from demo_resolver import DemoResolver

NAME = "calculator"


def resolve(resolver: DemoResolver) -> None:
    # The stack machine: the one function with a switch of 10 cases or more. (Unoptimized, GCC
    # compiles this switch as a chain of compares, which Hex-Rays shows as ifs: no match.)
    machine = Function().structured_with(switch_cases=(10, None))

    # The lexer: calling strtod, with a loop skipping blanks and one reading names.
    lexer = Function().calls(PLTEntry("strtod")).structured_with(loops=(2, None))

    # The variables' hash table: hashing a name in a loop, then probing in another.
    variables = Function().references(String().matching("^unknown variable")).structured_with(loops=(2, None))

    # The parser's innermost rule, by the error it reports; then the recursive descent: what it
    # leads to that leads back to it.
    factor = Function().references(String("expected ')'"))
    grammar = Function().called_by(factor, max_depth=None).calls(factor, max_depth=None)

    # Of the grammar's rules, those looping over their operators: a term's (* / %), an expression's (+ -).
    binary_operators = grammar.structured_with(loops=1)

    resolver.resolve_all(machine, ["calc::run"])
    resolver.resolve(lexer, "calc::next_token")
    resolver.resolve(variables, "calc::variable_slot")
    resolver.resolve(factor, "calc::parse_factor")
    resolver.resolve_all(grammar, ["calc::parse_factor", "calc::parse_term", "calc::parse_expression"])
    resolver.resolve_all(binary_operators, ["calc::parse_term", "calc::parse_expression"])


SOURCE = r"""
// calc: a calculator language, with variables. A lexer cuts a line into tokens, a
// recursive-descent parser compiles them into bytecode, and a stack machine runs
// it. Each part has a shape of its own, as Hex-Rays decompiles it: the machine's
// switch, the lexer's loops, the parser's recursion.

#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// No inlining, cloning nor folding: each function stays one, as a function with many callers would.
#define KEEP __attribute__((noipa))

namespace calc {

enum class TokenKind { Number, Name, Plus, Minus, Star, Slash, Percent, Caret, LeftParen, RightParen, Assign, End, Error };

struct Token {
    TokenKind kind;
    double number;
    char name[32];
};

enum Opcode : unsigned char { PUSH, LOAD, STORE, ADD, SUBTRACT, MULTIPLY, DIVIDE, MODULO, POWER, NEGATE, PRINT, HALT };

struct Instruction {
    Opcode opcode;
    int slot;
    double operand;
};

struct Variable {
    char name[32];
    double value;
    bool used;
};

constexpr int MAX_VARIABLES = 64;
constexpr int MAX_PROGRAM = 256;

Variable variables[MAX_VARIABLES];
Instruction program[MAX_PROGRAM];
int program_length;
const char* source;
int position;
Token current;
bool failed;

KEEP void report_error(const char* message, const char* detail) {
    std::fprintf(stderr, "error: %s%s\n", message, detail);
    failed = true;
}

// Open addressing: the slot of `name`, hashed, or the first free one after it.
KEEP int variable_slot(const char* name, bool create) {
    unsigned hash = 0;
    for (const char* c = name; *c != '\0'; ++c)
        hash = hash * 31 + static_cast<unsigned char>(*c);
    for (int probe = 0; probe < MAX_VARIABLES; ++probe) {
        int slot = static_cast<int>((hash + probe) % MAX_VARIABLES);
        if (!variables[slot].used) {
            if (!create) {
                report_error("unknown variable: ", name);
                return -1;
            }
            std::strcpy(variables[slot].name, name);
            variables[slot].used = true;
            return slot;
        }
        if (std::strcmp(variables[slot].name, name) == 0)
            return slot;
    }
    report_error("too many variables", "");
    return -1;
}

KEEP void next_token() {
    Token token{};
    while (source[position] == ' ' || source[position] == '\t')
        position++;
    char c = source[position];
    if (c == '\0') {
        token.kind = TokenKind::End;
    } else if (std::isdigit(static_cast<unsigned char>(c)) || c == '.') {
        char* end;
        token.kind = TokenKind::Number;
        token.number = std::strtod(source + position, &end);
        position = static_cast<int>(end - source);
    } else if (std::isalpha(static_cast<unsigned char>(c))) {
        int length = 0;
        while (std::isalnum(static_cast<unsigned char>(source[position])) && length < 31)
            token.name[length++] = source[position++];
        token.kind = TokenKind::Name;
    } else {
        position++;
        const char* operators = "+-*/%^()=";
        const char* found = std::strchr(operators, c);
        token.kind = found != nullptr ? static_cast<TokenKind>(static_cast<int>(TokenKind::Plus) + (found - operators)) : TokenKind::Error;
        if (found == nullptr)
            report_error("unexpected character: ", source + position - 1);
    }
    current = token;
}

KEEP void emit(Opcode opcode, int slot, double operand) {
    if (program_length >= MAX_PROGRAM) {
        report_error("program too long", "");
        return;
    }
    program[program_length++] = {opcode, slot, operand};
}

KEEP void parse_expression();

// A number, a variable, a parenthesized expression, or a negated factor; then maybe a power.
KEEP void parse_factor() {
    if (current.kind == TokenKind::Number) {
        emit(PUSH, 0, current.number);
        next_token();
    } else if (current.kind == TokenKind::Name) {
        emit(LOAD, variable_slot(current.name, false), 0);
        next_token();
    } else if (current.kind == TokenKind::LeftParen) {
        next_token();
        parse_expression();
        if (current.kind != TokenKind::RightParen)
            report_error("expected ')'", "");
        next_token();
    } else if (current.kind == TokenKind::Minus) {
        next_token();
        parse_factor();
        emit(NEGATE, 0, 0);
    } else {
        report_error("expected a number, a variable or '('", "");
        next_token();
    }
    if (current.kind == TokenKind::Caret) {
        next_token();
        parse_factor();
        emit(POWER, 0, 0);
    }
}

KEEP void parse_term() {
    parse_factor();
    while (current.kind == TokenKind::Star || current.kind == TokenKind::Slash || current.kind == TokenKind::Percent) {
        TokenKind operation = current.kind;
        next_token();
        parse_factor();
        emit(operation == TokenKind::Star ? MULTIPLY : operation == TokenKind::Slash ? DIVIDE : MODULO, 0, 0);
    }
}

KEEP void parse_expression() {
    parse_term();
    while (current.kind == TokenKind::Plus || current.kind == TokenKind::Minus) {
        TokenKind operation = current.kind;
        next_token();
        parse_term();
        emit(operation == TokenKind::Plus ? ADD : SUBTRACT, 0, 0);
    }
}

// "name = expression", or an expression to print.
KEEP bool compile(const char* line) {
    source = line;
    position = 0;
    program_length = 0;
    failed = false;
    next_token();
    if (current.kind == TokenKind::Name) {
        int saved_position = position;
        Token name = current;
        next_token();
        if (current.kind == TokenKind::Assign) {
            next_token();
            parse_expression();
            emit(STORE, variable_slot(name.name, true), 0);
            emit(HALT, 0, 0);
            return !failed;
        }
        position = saved_position;
        current = name;
    }
    parse_expression();
    emit(PRINT, 0, 0);
    emit(HALT, 0, 0);
    return !failed;
}

KEEP double run() {
    double stack[64];
    int top = 0;
    for (int pc = 0; pc < program_length; ++pc) {
        const Instruction& instruction = program[pc];
        switch (instruction.opcode) {
            case PUSH: stack[top++] = instruction.operand; break;
            case LOAD: stack[top++] = variables[instruction.slot].value; break;
            case STORE: variables[instruction.slot].value = stack[top - 1]; break;
            case ADD: top--; stack[top - 1] += stack[top]; break;
            case SUBTRACT: top--; stack[top - 1] -= stack[top]; break;
            case MULTIPLY: top--; stack[top - 1] *= stack[top]; break;
            case DIVIDE:
                top--;
                if (stack[top] == 0) {
                    report_error("division by zero", "");
                    return 0;
                }
                stack[top - 1] /= stack[top];
                break;
            case MODULO: top--; stack[top - 1] = std::fmod(stack[top - 1], stack[top]); break;
            case POWER: top--; stack[top - 1] = std::pow(stack[top - 1], stack[top]); break;
            case NEGATE: stack[top - 1] = -stack[top - 1]; break;
            case PRINT: std::printf("%g\n", stack[top - 1]); break;
            case HALT: return top > 0 ? stack[top - 1] : 0;
        }
    }
    return top > 0 ? stack[top - 1] : 0;
}

}  // namespace calc

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i)
        if (calc::compile(argv[i]))
            calc::run();
    return 0;
}
"""
