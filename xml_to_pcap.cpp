#include <iostream>
#include <tinyxml.h>
#include "Dumper.h"
#include "XMLDecoder.h"

void usage(const char *app)
{
    std::cout << "\t" << app << "  input.xml output.cap \n";
    std::cout << "\t" << app << "  -h\n";
}

std::pair<char *, char *> ParseCLI(int argc, char **argv)
{
    if (argc == 3) {
        return std::pair<char *, char *>(argv[1], argv[2]);
    } else {
        usage(argv[0]);
        exit(1);
    }
}

#include "tinyxml.h"

// ----------------------------------------------------------------------
// STDOUT dump and indenting utility functions
// ----------------------------------------------------------------------
const unsigned int NUM_INDENTS_PER_SPACE = 2;

const char *getIndent(unsigned int numIndents)
{
    static const char *pINDENT = "                                      + ";
    static const unsigned int LENGTH = strlen(pINDENT);
    unsigned int n = numIndents * NUM_INDENTS_PER_SPACE;
    if (n > LENGTH) n = LENGTH;

    return &pINDENT[LENGTH - n];
}

// same as getIndent but no "+" at the end
const char *getIndentAlt(unsigned int numIndents)
{
    static const char *pINDENT = "                                        ";
    static const unsigned int LENGTH = strlen(pINDENT);
    unsigned int n = numIndents * NUM_INDENTS_PER_SPACE;
    if (n > LENGTH) n = LENGTH;

    return &pINDENT[LENGTH - n];
}

int dump_attribs_to_stdout(TiXmlElement *pElement, unsigned int indent)
{
    if (!pElement) return 0;

    TiXmlAttribute *pAttrib = pElement->FirstAttribute();
    int i = 0;
    int ival;
    double dval;
    const char *pIndent = getIndent(indent);
    printf("\n");
    while (pAttrib) {
        printf("%s%s: value=[%s]", pIndent, pAttrib->Name(), pAttrib->Value());

        if (pAttrib->QueryIntValue(&ival) == TIXML_SUCCESS) printf(" int=%d", ival);
        if (pAttrib->QueryDoubleValue(&dval) == TIXML_SUCCESS) printf(" d=%1.1f", dval);
        printf("\n");
        i++;
        pAttrib = pAttrib->Next();
    }
    return i;
}

void dump_to_stdout(TiXmlNode *pParent, unsigned int indent = 0)
{
    if (!pParent) return;

    TiXmlNode *pChild;
    TiXmlText *pText;
    int t = pParent->Type();
    printf("%s", getIndent(indent));
    int num;

    switch (t) {
        case TiXmlNode::TINYXML_DOCUMENT:
            printf("Document");
            break;

        case TiXmlNode::TINYXML_ELEMENT:
            printf("Element [%s]", pParent->Value());
            num = dump_attribs_to_stdout(pParent->ToElement(), indent + 1);
            switch (num) {
                case 0:
                    printf(" (No attributes)");
                    break;
                case 1:
                    printf("%s1 attribute", getIndentAlt(indent));
                    break;
                default:
                    printf("%s%d attributes", getIndentAlt(indent), num);
                    break;
            }
            break;

        case TiXmlNode::TINYXML_COMMENT:
            printf("Comment: [%s]", pParent->Value());
            break;

        case TiXmlNode::TINYXML_UNKNOWN:
            printf("Unknown");
            break;

        case TiXmlNode::TINYXML_TEXT:
            pText = pParent->ToText();
            printf("Text: [%s]", pText->Value());
            break;

        case TiXmlNode::TINYXML_DECLARATION:
            printf("Declaration");
            break;
        default:
            break;
    }
    printf("\n");
    for (pChild = pParent->FirstChild(); pChild != 0; pChild = pChild->NextSibling()) {
        dump_to_stdout(pChild, indent + 1);
    }
}

int main(int argc, char **argv)
{
    std::pair<char *, char *> args = ParseCLI(argc, argv);
    TiXmlDocument doc(args.first);
    if (!doc.LoadFile()) {
        std::cerr << "Could not read file " << args.first << "\n";
        return 1;
    }

    Dumper dumper(args.second);
    if (!dumper.IsOpened()) {
        std::cerr << "Could not write file " << args.second << "\n";
        return 1;
    }

    std::cout << "  Parsing " << args.first << ";  Write pcap into " << args.second << "\n";
    TiXmlNode *decl = doc.FirstChild();
    if (!decl) {
        std::cerr << " Wrong format: no declaration in  " << args.first << "\n";
        return 2;
    }
    TiXmlNode* file = decl->NextSibling();
    if (!file) {
        std::cerr << " Wrong format: no <file> tag in " << args.first << "\n";
        return 2;
    }
    for (auto pack = file->FirstChild(); pack; pack = pack->NextSibling())
        ParsePacket(pack->ToElement(), dumper);

//    dump_to_stdout(&doc);

}