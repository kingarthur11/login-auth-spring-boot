package com.walletsecurity.userlogin;

import java.util.List;

public class Practice {

    public static void main(String[] args) {

        List<Integer> numbers = List.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
        numbers.stream().filter(n -> n % 2 == 0).map(number -> number * number).forEach(System.out::print);
//        numbers.stream().filter(n -> n % 2 == 0).forEach(System.out::print);
//        numbers.stream().filter(Practice::isEven).forEach(System.out::print);
//        numbers.stream().forEach(System.out::println);
//        numbers.stream().forEach(Practice::printNumbers);
//        for (int number : numbers) {
//            printNumbers(number);
//        }
        System.out.println("hello world");
    }

//    public static void printNumbers(int number) {
//        System.out.println(number);
//    }
    public static boolean isEven(int number) {
        return number % 2 == 0;
    }
}
